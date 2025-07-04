package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
)

// RefreshToken handles token refresh
func (s *AuthService) RefreshToken(ctx context.Context, sessionID string) (*dto.RefreshTokenResponse, error) {
	// Validate refresh token
	session, err := s.Auth.Repository.GetSessionRepository().GetSessionBySessionID(ctx, sessionID)
	if err != nil {
		return nil, errors.New("invalid session")
	}

	userID := session.UserID
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Generate new tokens
	accessToken, refreshToken, err := s.Auth.TokenManager.GenerateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}
	hashedRefreshToken, err := s.Auth.TokenManager.HashToken(refreshToken)
	if err != nil {
		return nil, errors.New("failed to hash refresh token")
	}
	session.RefreshToken = hashedRefreshToken
	// update session itself
	session.ExpiresAt = time.Now().Add(s.Auth.Config.AuthConfig.JWT.AccessTokenTTL)
	err = s.Auth.Repository.GetSessionRepository().UpdateSession(ctx, session)
	if err != nil {
		return nil, errors.New("failed to update session")
	}
	return &dto.RefreshTokenResponse{
		Message: "token refreshed successfully",
		Tokens: dto.TokenData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(s.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		},
	}, nil
}
