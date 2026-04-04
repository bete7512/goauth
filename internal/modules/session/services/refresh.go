package services

import (
	"context"
	"errors"
	"time"

	"github.com/bete7512/goauth/internal/modules/session/handlers/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// Refresh refreshes the access token using a refresh token
func (s *sessionService) Refresh(ctx context.Context, req *dto.RefreshRequest) (dto.AuthResponse, *types.GoAuthError) {
	// Hash the incoming refresh token and look up by hash
	tokenHash := s.securityManager.HashRefreshToken(req.RefreshToken)
	session, err := s.sessionRepository.FindByToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return dto.AuthResponse{}, types.NewInvalidCredentialsError()
		}
		return dto.AuthResponse{}, types.NewInternalError("failed to find session by token").Wrap(err)
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
	}

	// Check if refresh token is expired
	if session.RefreshTokenExpiresAt.Before(time.Now()) {
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
	}

	// Get user
	user, err := s.userRepository.FindByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return dto.AuthResponse{}, types.NewInvalidCredentialsError()
		}
		return dto.AuthResponse{}, types.NewInternalError("failed to find user").Wrap(err)
	}

	// Run auth interceptors for refresh (enrichment only, no challenges)
	interceptClaims, _, responseData, interceptErr := s.deps.AuthInterceptors.Run(ctx, &types.InterceptParams{
		Phase: types.PhaseRefresh,
		User:  user,
	})
	if interceptErr != nil {
		return dto.AuthResponse{}, types.NewInternalError("Token refresh interrupted")
	}

	// Generate new session ID for rotation
	newSessionID := uuid.Must(uuid.NewV7()).String()

	// Merge interceptor claims with session_id
	tokenClaims := map[string]interface{}{"session_id": newSessionID}
	for k, v := range interceptClaims {
		tokenClaims[k] = v
	}

	// Generate new tokens with enriched claims
	accessToken, newRefreshToken, err := s.securityManager.GenerateTokens(user, tokenClaims)
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError("failed to generate tokens").Wrap(err)
	}

	// Delete old session by hash
	if err := s.sessionRepository.DeleteByToken(ctx, tokenHash); err != nil {
		return dto.AuthResponse{}, types.NewInternalError("failed to rotate session").Wrap(err)
	}

	// Create new session with hashed rotated refresh token
	session.ID = newSessionID
	session.RefreshToken = s.securityManager.HashRefreshToken(newRefreshToken)
	session.RefreshTokenExpiresAt = time.Now().Add(s.deps.Config.Security.Session.RefreshTokenTTL)
	session.ExpiresAt = time.Now().Add(s.deps.Config.Security.Session.SessionTTL)
	session.CreatedAt = time.Now()
	session.UpdatedAt = time.Now()

	if err := s.sessionRepository.Create(ctx, session); err != nil {
		return dto.AuthResponse{}, types.NewInternalError("failed to create refreshed session").Wrap(err)
	}

	return dto.AuthResponse{
		AccessToken:        accessToken,
		RefreshToken:       newRefreshToken,
		ExpiresIn:          int64(s.deps.Config.Security.Session.SessionTTL.Seconds()),
		Message:            "Token refreshed successfully",
		SessionID:          newSessionID,
		Data:               responseData,
	}, nil
}
