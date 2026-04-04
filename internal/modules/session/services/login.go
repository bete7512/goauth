package services

import (
	"context"
	"errors"
	"time"

	"github.com/bete7512/goauth/internal/modules/session/handlers/dto"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Login authenticates user and creates session
func (s *sessionService) Login(ctx context.Context, req *dto.LoginRequest, metadata *types.RequestMetadata) (dto.AuthResponse, *types.GoAuthError) {
	// Find user
	user, err := s.userRepository.FindByEmail(ctx, req.Email)
	if err != nil {
		if !errors.Is(err, models.ErrNotFound) {
			return dto.AuthResponse{}, types.NewInternalError("failed to find user").Wrap(err)
		}
		// user not found by email, try username
		if req.Username != "" {
			user, err = s.userRepository.FindByUsername(ctx, req.Username)
			if err != nil {
				if !errors.Is(err, models.ErrNotFound) {
					return dto.AuthResponse{}, types.NewInternalError("failed to find user by username").Wrap(err)
				}
				return dto.AuthResponse{}, types.NewInvalidCredentialsError()
			}
		} else {
			return dto.AuthResponse{}, types.NewInvalidCredentialsError()
		}
	}

	// Check account lockout
	lockoutCfg := security.NormalizeLockoutConfig(s.deps.Config.Security.Lockout)
	if authErr := security.CheckLockout(user, lockoutCfg); authErr != nil {
		return dto.AuthResponse{}, authErr
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return dto.AuthResponse{}, security.HandleFailedLogin(ctx, user, lockoutCfg, s.userRepository, s.deps.Events, s.deps.Logger)
	}

	// Clear any failed-attempt state on successful password check
	security.RecordSuccessfulLogin(user)

	// Run auth interceptors (2FA challenges, org enrichment, etc.)
	interceptClaims, challenges, responseData, interceptErr := s.deps.AuthInterceptors.Run(ctx, &types.InterceptParams{
		Phase:    types.PhaseLogin,
		User:     user,
		Metadata: metadata,
	})
	if interceptErr != nil {
		s.logger.Errorf("session: auth interceptor failed: %v", interceptErr)
		return dto.AuthResponse{}, types.NewInternalError("Authentication flow interrupted")
	}

	// If any challenges were issued, return them without tokens
	if len(challenges) > 0 {
		return dto.AuthResponse{
			Challenges: challenges,
			Message:    "Authentication challenge required",
		}, nil
	}

	// Generate session ID first so it can be embedded in the JWT
	sessionID := uuid.Must(uuid.NewV7()).String()

	// Merge interceptor claims with session_id
	tokenClaims := map[string]interface{}{"session_id": sessionID}
	for k, v := range interceptClaims {
		tokenClaims[k] = v
	}

	// Generate tokens with enriched claims
	accessToken, refreshToken, err := s.securityManager.GenerateTokens(user, tokenClaims)
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError("failed to generate tokens").Wrap(err)
	}

	// Create session — store a SHA-256 hash of the refresh token, not the raw token
	session := &models.Session{
		ID:                    sessionID,
		UserID:                user.ID,
		RefreshToken:          security.HashRefreshToken(refreshToken),
		RefreshTokenExpiresAt: time.Now().Add(s.deps.Config.Security.Session.RefreshTokenTTL),
		ExpiresAt:             time.Now().Add(s.deps.Config.Security.Session.SessionTTL),
		UserAgent:             metadata.UserAgent,
		IPAddress:             metadata.IPAddress,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	if err := s.sessionRepository.Create(ctx, session); err != nil {
		return dto.AuthResponse{}, types.NewInternalError("failed to create session").Wrap(err)
	}

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.userRepository.Update(ctx, user); err != nil {
		s.logger.Errorf("failed to update user last login time: %v", err)
	}

	return dto.AuthResponse{
		AccessToken:        accessToken,
		RefreshToken:       refreshToken,
		SessionID:          sessionID,
		User:               dto.UserToDTO(user),
		ExpiresIn:          int64(s.deps.Config.Security.Session.SessionTTL.Seconds()),
		Message:            "Login successful",
		Data:               responseData,
	}, nil
}
