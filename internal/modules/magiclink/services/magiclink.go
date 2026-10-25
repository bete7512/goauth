package services

//go:generate mockgen -destination=../../../mocks/mock_magiclink_service.go -package=mocks github.com/bete7512/goauth/internal/modules/magiclink/services MagicLinkService

import (
	"context"
	"errors"
	"fmt"
	"github.com/bete7512/goauth/internal/authentication"
	"github.com/bete7512/goauth/internal/security"
	"strings"
	"time"

	coredto "github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/magiclink/handlers/dto"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// MagicLinkService defines the magic link passwordless authentication operations.
type MagicLinkService interface {
	SendMagicLink(ctx context.Context, req *dto.MagicLinkSendRequest) (*coredto.MessageResponse, *types.GoAuthError)
	VerifyMagicLink(ctx context.Context, token string) (*coredto.AuthResponse, *types.GoAuthError)
	VerifyByCode(ctx context.Context, req *dto.MagicLinkVerifyByCodeRequest) (*coredto.AuthResponse, *types.GoAuthError)
	ResendMagicLink(ctx context.Context, req *dto.MagicLinkSendRequest) (*coredto.MessageResponse, *types.GoAuthError)
}

type magicLinkService struct {
	deps            config.ModuleDependencies
	config          *config.MagicLinkModuleConfig
	userRepository  models.UserRepository
	tokenRepository models.TokenRepository
	securityManager types.SecurityManager
	logger          logger.Logger
}

func NewMagicLinkService(
	deps config.ModuleDependencies,
	userRepo models.UserRepository,
	tokenRepo models.TokenRepository,
	securityManager types.SecurityManager,
	cfg *config.MagicLinkModuleConfig,
) *magicLinkService {
	return &magicLinkService{
		deps:            deps,
		config:          cfg,
		userRepository:  userRepo,
		tokenRepository: tokenRepo,
		securityManager: securityManager,
		logger:          deps.Logger,
	}
}

func (s *magicLinkService) SendMagicLink(ctx context.Context, req *dto.MagicLinkSendRequest) (*coredto.MessageResponse, *types.GoAuthError) {
	genericMsg := &coredto.MessageResponse{Message: "If an account exists, a magic link has been sent"}

	user, err := s.userRepository.FindByEmail(ctx, req.Email)
	if err != nil || user == nil { //nolint:gocritic // intentionally combined: both DB error and not-found trigger auto-register or generic message
		if s.config.AutoRegister {
			newUser, authErr := s.autoRegister(ctx, req.Email)
			if authErr != nil {
				return nil, authErr
			}
			user = newUser
		} else {
			// Don't reveal whether user exists
			return genericMsg, nil
		}
	}

	return s.sendMagicLinkForUser(ctx, user)
}

func (s *magicLinkService) ResendMagicLink(ctx context.Context, req *dto.MagicLinkSendRequest) (*coredto.MessageResponse, *types.GoAuthError) {
	return s.SendMagicLink(ctx, req)
}

func (s *magicLinkService) VerifyMagicLink(ctx context.Context, tokenStr string) (*coredto.AuthResponse, *types.GoAuthError) {
	verification, err := security.FindByTokenDigest(ctx, tokenStr, s.tokenRepository.FindByToken)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewGoAuthError(types.ErrInvalidToken, "invalid magic link token", 400)
		}
		return nil, types.NewInternalError("failed to find magic link token").Wrap(err)
	}

	return s.verifyToken(ctx, verification)
}

func (s *magicLinkService) VerifyByCode(ctx context.Context, req *dto.MagicLinkVerifyByCodeRequest) (*coredto.AuthResponse, *types.GoAuthError) {
	// Resolve by email + type first so we can rate-limit attempts even when the
	// submitted code is wrong (otherwise brute-force would never increment).
	verification, err := s.tokenRepository.FindByEmailAndType(ctx, req.Email, models.TokenTypeMagicLink)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewGoAuthError(types.ErrInvalidToken, "invalid email or code", 400)
		}
		return nil, types.NewInternalError("failed to find magic link code").Wrap(err)
	}

	maxAttempts := s.maxCodeAttempts()
	if verification.Attempts >= maxAttempts {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "too many attempts, request a new code", 429)
	}

	if !security.CodeMatches(s.codeKey(), verification.ID, verification.Code, req.Code) {
		if _, incErr := s.tokenRepository.IncrementAttempts(ctx, verification.ID); incErr != nil {
			s.logger.Errorf("magiclink: failed to increment attempts: %v", incErr)
		}
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "invalid email or code", 400)
	}

	return s.verifyToken(ctx, verification)
}

// --- Internal helpers ---

func (s *magicLinkService) sendMagicLinkForUser(ctx context.Context, user *models.User) (*coredto.MessageResponse, *types.GoAuthError) {
	// Delete existing magic link token for this email
	existing, err := s.tokenRepository.FindByEmailAndType(ctx, user.Email, models.TokenTypeMagicLink)
	if err == nil && existing != nil {
		s.tokenRepository.DeleteByIDAndType(ctx, existing.ID, models.TokenTypeMagicLink)
	}

	// Generate token + OTP code
	token, err := s.securityManager.GenerateRandomToken(32)
	if err != nil {
		return nil, types.NewInternalError("failed to generate token").Wrap(err)
	}

	code, err := s.securityManager.GenerateNumericOTP(6)
	if err != nil {
		return nil, types.NewInternalError("failed to generate code").Wrap(err)
	}

	tokenID := uuid.Must(uuid.NewV7()).String()
	magicLinkToken := &models.Token{
		ID:        tokenID,
		UserID:    user.ID,
		Token:     security.TokenDigest(token),
		Code:      security.CodeDigest(s.codeKey(), tokenID, code),
		Type:      models.TokenTypeMagicLink,
		Email:     user.Email,
		ExpiresAt: time.Now().Add(s.tokenExpiry()),
		Used:      false,
		CreatedAt: time.Now(),
	}

	if err := s.tokenRepository.Create(ctx, magicLinkToken); err != nil {
		return nil, types.NewInternalError("failed to create magic link token").Wrap(err)
	}

	mode := s.deliveryMode()
	expiryMinutes := int(s.tokenExpiry().Minutes())

	eventData := &types.MagicLinkRequestData{
		User:         user,
		DeliveryMode: mode,
		ExpiryTime:   fmt.Sprintf("%d minutes", expiryMinutes),
	}
	if mode != types.MagicLinkDeliveryModeCode {
		eventData.MagicLink = s.buildMagicLink(token)
	}
	if mode != types.MagicLinkDeliveryModeLink {
		eventData.Code = code
	}

	s.deps.Events.EmitAsync(ctx, types.EventSendMagicLink, eventData)

	return &coredto.MessageResponse{Message: "If an account exists, a magic link has been sent"}, nil
}

func (s *magicLinkService) verifyToken(ctx context.Context, verification *models.Token) (*coredto.AuthResponse, *types.GoAuthError) {
	if verification.ExpiresAt.Before(time.Now()) {
		return nil, types.NewGoAuthError(types.ErrTokenExpired, "magic link has expired", 400)
	}

	if verification.Used {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "magic link has already been used", 400)
	}

	if verification.Type != models.TokenTypeMagicLink {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "invalid token type", 400)
	}

	user, err := s.userRepository.FindByID(ctx, verification.UserID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewUserNotFoundError()
		}
		return nil, types.NewInternalError("failed to find user").Wrap(err)
	}

	// Mark token as used
	if err := s.tokenRepository.MarkAsUsed(ctx, verification.ID); err != nil {
		return nil, types.NewInternalError("failed to mark token as used").Wrap(err)
	}

	completion := authentication.ForModule(s.deps, s.tokenRepository, nil, "")
	result, authErr := completion.Complete(ctx, types.AuthenticationEvidence{User: user, Method: "magic_link"})
	if authErr != nil {
		return nil, authErr
	}
	if result.Status == types.ChallengeRequired {
		return &coredto.AuthResponse{Challenges: result.Challenges, Message: "Authentication challenge required"}, nil
	}
	accessToken, refreshToken := result.AccessToken, result.RefreshToken

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.userRepository.Update(ctx, user); err != nil {
		s.logger.Errorf("magiclink: failed to update last login: %v", err)
	}

	// Emit verification event
	s.deps.Events.EmitAsync(ctx, types.EventAfterMagicLinkVerified, &types.UserEventData{
		User: user,
	})

	expiresIn := int64(s.deps.Config.Security.Session.AccessTokenTTL.Seconds())

	return &coredto.AuthResponse{
		AccessToken:  &accessToken,
		RefreshToken: &refreshToken,
		User:         userToDTO(user),
		ExpiresIn:    expiresIn,
		Message:      "Magic link verified successfully",
	}, nil
}

func (s *magicLinkService) autoRegister(ctx context.Context, email string) (*models.User, *types.GoAuthError) {
	now := time.Now()
	user := &models.User{
		ID:            uuid.Must(uuid.NewV7()).String(),
		Email:         email,
		Username:      generateUsernameFromEmail(email),
		Active:        true,
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     &now,
	}

	if err := s.userRepository.Create(ctx, user); err != nil {
		return nil, types.NewInternalError("failed to auto-register user").Wrap(err)
	}

	s.logger.Infof("magiclink: auto-registered user %s", email)
	return user, nil
}

func (s *magicLinkService) tokenExpiry() time.Duration {
	if s.config.TokenExpiry > 0 {
		return s.config.TokenExpiry
	}
	return 10 * time.Minute
}

func (s *magicLinkService) deliveryMode() types.MagicLinkDeliveryMode {
	switch s.config.DeliveryMode {
	case types.MagicLinkDeliveryModeLink, types.MagicLinkDeliveryModeCode, types.MagicLinkDeliveryModeBoth:
		return s.config.DeliveryMode
	default:
		return types.MagicLinkDeliveryModeBoth
	}
}

// codeKey is the key for short-code digests, derived from the JWT secret.
func (s *magicLinkService) codeKey() []byte {
	if s.deps.Config == nil {
		return security.CodeKey(types.SecurityConfig{})
	}
	return security.CodeKey(s.deps.Config.Security)
}

func (s *magicLinkService) maxCodeAttempts() int {
	if s.config.MaxCodeAttempts > 0 {
		return s.config.MaxCodeAttempts
	}
	return 5
}

func (s *magicLinkService) buildMagicLink(token string) string {
	if s.deps.Config.APIURL == "" {
		return ""
	}
	apiURL := s.deps.Config.APIURL + s.deps.Config.BasePath
	return fmt.Sprintf("%s/magic-link/verify?token=%s", apiURL, token)
}

func generateUsernameFromEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0] + "-" + uuid.Must(uuid.NewV7()).String()[:8]
	}
	return "user-" + uuid.Must(uuid.NewV7()).String()[:8]
}

func userToDTO(user *models.User) *coredto.UserDTO {
	return &coredto.UserDTO{
		ID:                  user.ID,
		FirstName:           user.FirstName,
		LastName:            user.LastName,
		Name:                user.Name,
		Email:               user.Email,
		Username:            user.Username,
		Avatar:              user.Avatar,
		PhoneNumber:         user.PhoneNumber,
		Active:              user.Active,
		EmailVerified:       user.EmailVerified,
		PhoneNumberVerified: user.PhoneNumberVerified,
		CreatedAt:           user.CreatedAt,
		UpdatedAt:           user.UpdatedAt,
		LastLoginAt:         user.LastLoginAt,
	}
}
