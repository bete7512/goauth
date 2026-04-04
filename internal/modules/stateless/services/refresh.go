package services

import (
	"context"
	"errors"
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
		return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
	}

	// Verify token type
	if tokenType, ok := claims["type"].(string); !ok || tokenType != "refresh" {
		return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
	}

	// Get JTI (nonce)
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
	}

	// Get User ID
	userID, ok := claims["user_id"].(string)
	if !ok || userID == "" {
		return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
	}

	// Check if JTI exists in database (is valid and not blacklisted/revoked)
	_, err = s.TokenRepository.FindByToken(ctx, jti)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			// If not found, it means it's revoked or never existed
			return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
		}
		return dto.AuthResponse{}, types.NewInternalError("failed to find token record").Wrap(err)
	}

	// Check if user exists
	user, err := s.UserRepository.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
		}
		return dto.AuthResponse{}, types.NewInternalError("failed to find user").Wrap(err)
	}

	// Revoke old nonce (delete from database - this is the rotation)
	if err := s.TokenRepository.Delete(ctx, jti); err != nil {
		return dto.AuthResponse{}, types.NewInternalError("failed to revoke used token").Wrap(err)
	}

	// Run auth interceptors for refresh (enrichment only)
	interceptClaims, _, responseData, interceptErr := s.Deps.AuthInterceptors.Run(ctx, &types.InterceptParams{
		Phase:          types.PhaseRefresh,
		User:           user,
		ExistingClaims: claims,
	})
	if interceptErr != nil {
		return dto.AuthResponse{}, types.NewInternalError("Token refresh interrupted")
	}

	// Generate new access token with enriched claims
	accessToken, err := s.SecurityManager.GenerateAccessToken(
		*user,
		interceptClaims,
	)
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError("failed to generate access token").Wrap(err)
	}

	// Generate new refresh token with new JTI
	newRefreshToken, newJti, err := s.SecurityManager.GenerateStatelessRefreshToken(user)
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError("failed to generate refresh token").Wrap(err)
	}

	// Save new nonce
	tokenModel := &models.Token{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		Type:      "refresh_nonce",
		Token:     newJti,
		ExpiresAt: time.Now().Add(s.Deps.Config.Security.Session.RefreshTokenTTL),
		CreatedAt: time.Now(),
	}
	if err := s.TokenRepository.Create(ctx, tokenModel); err != nil {
		return dto.AuthResponse{}, types.NewInternalError("failed to save refresh token nonce").Wrap(err)
	}

	return dto.AuthResponse{
		AccessToken:  &accessToken,
		RefreshToken: &newRefreshToken,
		ExpiresIn:    int64(s.Deps.Config.Security.Session.SessionTTL.Seconds()),
		Message:      "Token refreshed successfully",
		Data:         responseData,
	}, nil
}
