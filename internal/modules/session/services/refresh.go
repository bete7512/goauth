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
func (s *SessionService) Refresh(ctx context.Context, req *dto.RefreshRequest) (dto.AuthResponse, *types.GoAuthError) {
	// Find session by refresh token
	session, err := s.SessionRepository.FindByToken(ctx, req.RefreshToken)
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
	user, err := s.UserRepository.FindByID(ctx, session.UserID)
	if err != nil || user == nil {
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
	}

	// Generate new tokens (with rotation)
	accessToken, newRefreshToken, err := s.SecurityManager.GenerateTokens(user, map[string]interface{}{})
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to generate tokens: %s", err.Error()))
	}

	// Delete old session
	if err := s.SessionRepository.DeleteByToken(ctx, req.RefreshToken); err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to rotate session: %s", err.Error()))
	}

	// Create new session with rotated refresh token
	session.ID = uuid.New().String()
	session.RefreshToken = newRefreshToken
	session.RefreshTokenExpiresAt = time.Now().Add(s.Deps.Config.Security.Session.RefreshTokenTTL)
	session.ExpiresAt = time.Now().Add(s.Deps.Config.Security.Session.SessionTTL)
	session.CreatedAt = time.Now()
	session.UpdatedAt = time.Now()

	if err := s.SessionRepository.Create(ctx, session); err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to create refreshed session: %s", err.Error()))
	}

	return dto.AuthResponse{
		AccessToken:  &accessToken,
		RefreshToken: &newRefreshToken,
		ExpiresIn:    int64(s.Deps.Config.Security.Session.SessionTTL.Seconds()),
		Message:      "Token refreshed successfully",
	}, nil
}

