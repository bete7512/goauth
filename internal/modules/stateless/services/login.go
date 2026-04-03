package services

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/stateless/handlers/dto"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Login authenticates user and generates JWT tokens with nonce-based refresh token
func (s *StatelessService) Login(ctx context.Context, req *dto.LoginRequest) (dto.AuthResponse, *types.GoAuthError) {
	// Find user
	user, err := s.UserRepository.FindByEmail(ctx, req.Email)
	if err != nil || user == nil {
		// Try by username if email not found
		if req.Username != "" {
			user, err = s.UserRepository.FindByUsername(ctx, req.Username)
		}
		if err != nil || user == nil {
			return dto.AuthResponse{}, types.NewInvalidCredentialsError()
		}
	}

	// Check account lockout
	lockoutCfg := security.NormalizeLockoutConfig(s.Deps.Config.Security.Lockout)
	if authErr := security.CheckLockout(user, lockoutCfg); authErr != nil {
		return dto.AuthResponse{}, authErr
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return dto.AuthResponse{}, security.HandleFailedLogin(ctx, user, lockoutCfg, s.UserRepository, s.Deps.Events, s.Deps.Logger)
	}

	// Clear any failed-attempt state on successful password check
	security.RecordSuccessfulLogin(user)

	// Run auth interceptors (2FA challenges, org enrichment, etc.)
	interceptClaims, challenges, interceptErr := s.Deps.AuthInterceptors.Run(ctx, &types.InterceptParams{
		Phase:    types.PhaseLogin,
		User:     user,
		Metadata: nil, // TODO: pass metadata from handler
	})
	if interceptErr != nil {
		s.Logger.Errorf("stateless: auth interceptor failed: %v", interceptErr)
		return dto.AuthResponse{}, types.NewInternalError("Authentication flow interrupted")
	}

	// If any challenges were issued, return them without tokens
	if len(challenges) > 0 {
		return dto.AuthResponse{
			Challenges: challenges,
			Message:    "Authentication challenge required",
		}, nil
	}

	// Generate access token with enriched claims
	accessToken, err := s.SecurityManager.GenerateAccessToken(
		*user,
		interceptClaims,
	)
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to generate access token: %s", err.Error()))
	}

	// Generate stateless refresh token with JTI (nonce)
	refreshToken, jti, err := s.SecurityManager.GenerateStatelessRefreshToken(user)
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to generate refresh token: %s", err.Error()))
	}

	// Store the JTI (nonce) in the tokens table for revocation checks
	tokenModel := &models.Token{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		Type:      "refresh_nonce",
		Token:     jti,
		ExpiresAt: time.Now().Add(s.Deps.Config.Security.Session.RefreshTokenTTL),
		CreatedAt: time.Now(),
	}
	if err := s.TokenRepository.Create(ctx, tokenModel); err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to save refresh token nonce: %s", err.Error()))
	}

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.UserRepository.Update(ctx, user); err != nil {
		s.Logger.Errorf("failed to update user last login time: %v", err)
	}

	return dto.AuthResponse{
		AccessToken:  &accessToken,
		RefreshToken: &refreshToken,
		User:         dto.UserToDTO(user),
		ExpiresIn:    int64(s.Deps.Config.Security.Session.SessionTTL.Seconds()),
		Message:      "Login successful",
	}, nil
}
