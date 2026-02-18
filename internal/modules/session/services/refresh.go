package services

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/session/handlers/dto"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// Refresh refreshes the access token using a refresh token
func (s *sessionService) Refresh(ctx context.Context, req *dto.RefreshRequest) (dto.AuthResponse, *types.GoAuthError) {
	// Find session by refresh token
	session, err := s.sessionRepository.FindByToken(ctx, req.RefreshToken)
	if err != nil || session == nil {
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
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
	if err != nil || user == nil {
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
	}

	// Generate new session ID for rotation
	newSessionID := uuid.New().String()

	// Generate new tokens with session_id in JWT claims
	accessToken, newRefreshToken, err := s.securityManager.GenerateTokens(user, map[string]interface{}{
		"session_id": newSessionID,
	})
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to generate tokens: %s", err.Error()))
	}

	// Delete old session
	if err := s.sessionRepository.DeleteByToken(ctx, req.RefreshToken); err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to rotate session: %s", err.Error()))
	}

	// Create new session with rotated refresh token
	session.ID = newSessionID
	session.RefreshToken = newRefreshToken
	session.RefreshTokenExpiresAt = time.Now().Add(s.deps.Config.Security.Session.RefreshTokenTTL)
	session.ExpiresAt = time.Now().Add(s.deps.Config.Security.Session.SessionTTL)
	session.CreatedAt = time.Now()
	session.UpdatedAt = time.Now()

	if err := s.sessionRepository.Create(ctx, session); err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to create refreshed session: %s", err.Error()))
	}

	return dto.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(s.deps.Config.Security.Session.SessionTTL.Seconds()),
		Message:      "Token refreshed successfully",
		SessionID:    newSessionID,
	}, nil
}
