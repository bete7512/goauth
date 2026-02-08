package services

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/stateless/handlers/dto"
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

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
	}

	// Generate access token
	accessToken, err := s.SecurityManager.GenerateAccessToken(
		*user,
		map[string]interface{}{},
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
		ID:        uuid.New().String(),
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
