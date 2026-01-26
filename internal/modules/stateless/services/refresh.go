package services

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/stateless/handlers/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// Refresh refreshes tokens using JWT refresh token with nonce validation
func (s *StatelessService) Refresh(ctx context.Context, req *dto.RefreshRequest) (dto.AuthResponse, *types.GoAuthError) {
	// Parse and validate JWT refresh token
	claims, err := s.SecurityManager.ValidateJWTToken(req.RefreshToken)
	if err != nil {
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
	}

	// Verify token type
	if tokenType, ok := claims["type"].(string); !ok || tokenType != "refresh" {
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
	}

	// Get JTI (nonce)
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
	}

	// Get User ID
	userID, ok := claims["user_id"].(string)
	if !ok || userID == "" {
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
	}

	// Check if JTI exists in database (is valid and not blacklisted/revoked)
	tokenRecord, err := s.TokenRepository.FindByToken(ctx, jti)
	if err != nil || tokenRecord == nil {
		// If not found, it means it's revoked or never existed
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
	}

	// Check if user exists
	user, err := s.UserRepository.FindByID(ctx, userID)
	if err != nil || user == nil {
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
	}

	// Revoke old nonce (delete from database - this is the rotation)
	if err := s.TokenRepository.Delete(ctx, jti); err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to revoke used token: %s", err.Error()))
	}

	// Generate new access token
	accessToken, err := s.SecurityManager.GenerateAccessToken(
		*user,
		map[string]interface{}{},
		s.Deps.Config.Security.Session.AccessTokenTTL,
		s.Deps.Config.Security.JwtSecretKey,
	)
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to generate access token: %s", err.Error()))
	}

	// Generate new refresh token with new JTI
	newRefreshToken, newJti, err := s.SecurityManager.GenerateStatelessRefreshToken(user)
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to generate refresh token: %s", err.Error()))
	}

	// Save new nonce
	tokenModel := &models.Token{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Type:      "refresh_nonce",
		Token:     newJti,
		ExpiresAt: time.Now().Add(s.Deps.Config.Security.Session.RefreshTokenTTL),
		CreatedAt: time.Now(),
	}
	if err := s.TokenRepository.Create(ctx, tokenModel); err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to save refresh token nonce: %s", err.Error()))
	}

	return dto.AuthResponse{
		AccessToken:  &accessToken,
		RefreshToken: &newRefreshToken,
		ExpiresIn:    int64(s.Deps.Config.Security.Session.SessionTTL.Seconds()),
		Message:      "Token refreshed successfully",
	}, nil
}
