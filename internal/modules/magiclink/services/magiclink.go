package services

//go:generate mockgen -destination=../../../mocks/mock_magiclink_service.go -package=mocks github.com/bete7512/goauth/internal/modules/magiclink/services MagicLinkService

import (
	"context"
	"fmt"
	"strings"
	"time"

	coredto "github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/magiclink/handlers/dto"
	"github.com/bete7512/goauth/internal/security"
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
	securityManager *security.SecurityManager
	logger          logger.Logger
}

func NewMagicLinkService(
	deps config.ModuleDependencies,
	userRepo models.UserRepository,
	tokenRepo models.TokenRepository,
	securityManager *security.SecurityManager,
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
	if err != nil || user == nil {
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
	verification, err := s.tokenRepository.FindByToken(ctx, tokenStr)
	if err != nil || verification == nil {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "invalid magic link token", 400)
	}

	return s.verifyToken(ctx, verification)
}

func (s *magicLinkService) VerifyByCode(ctx context.Context, req *dto.MagicLinkVerifyByCodeRequest) (*coredto.AuthResponse, *types.GoAuthError) {
	verification, err := s.tokenRepository.FindByCode(ctx, req.Code, models.TokenTypeMagicLink)
	if err != nil || verification == nil {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "invalid magic link code", 400)
	}

	if verification.Email != req.Email {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "code does not match email", 400)
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
		return nil, types.NewInternalError(fmt.Sprintf("failed to generate token: %v", err))
	}

	code, err := s.securityManager.GenerateNumericOTP(6)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to generate code: %v", err))
	}

	magicLinkToken := &models.Token{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     token,
		Code:      code,
		Type:      models.TokenTypeMagicLink,
		Email:     user.Email,
		ExpiresAt: time.Now().Add(s.tokenExpiry()),
		Used:      false,
		CreatedAt: time.Now(),
	}

	if err := s.tokenRepository.Create(ctx, magicLinkToken); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to create magic link token: %v", err))
	}

	magicLink := s.buildMagicLink(token)
	expiryMinutes := int(s.tokenExpiry().Minutes())

	s.deps.Events.EmitAsync(ctx, types.EventSendMagicLink, &types.MagicLinkRequestData{
		User:       user,
		MagicLink:  magicLink,
		Code:       code,
		ExpiryTime: fmt.Sprintf("%d minutes", expiryMinutes),
	})

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
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}

	// Mark token as used
	if err := s.tokenRepository.MarkAsUsed(ctx, verification.ID); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to mark token as used: %v", err))
	}

	// Generate auth tokens
	accessToken, refreshToken, err := s.securityManager.GenerateTokens(user, map[string]interface{}{})
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to generate tokens: %v", err))
	}

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
		ID:            uuid.New().String(),
		Email:         email,
		Username:      generateUsernameFromEmail(email),
		Active:        true,
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     &now,
	}

	if err := s.userRepository.Create(ctx, user); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to auto-register user: %v", err))
	}

	s.logger.Infof("magiclink: auto-registered user %s", email)
	return user, nil
}

func (s *magicLinkService) tokenExpiry() time.Duration {
	if s.config.TokenExpiry > 0 {
		return s.config.TokenExpiry
	}
	return 15 * time.Minute
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
		return parts[0] + "-" + uuid.New().String()[:8]
	}
	return "user-" + uuid.New().String()[:8]
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
