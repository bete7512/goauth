package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
)

// SendMagicLink handles magic link request
func (s *AuthService) SendMagicLink(ctx context.Context, req *dto.MagicLinkRequest) error {
	// Get user by email
	user, err := s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		// Don't reveal if user exists or not
		return nil
	}

	// Generate magic link token
	magicToken, err := s.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate magic link token: %w", err)
	}

	hashedToken, err := s.Auth.TokenManager.HashToken(magicToken)
	if err != nil {
		return fmt.Errorf("failed to hash magic link token: %w", err)
	}
	existingToken, err := s.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(ctx, user.ID, models.MakicLinkToken)
	if err != nil {
		return fmt.Errorf("failed to get existing token: %w", err)
	}
	if existingToken != nil {
		err = s.Auth.Repository.GetTokenRepository().RevokeToken(ctx, existingToken.ID)
		if err != nil {
			return fmt.Errorf("failed to revoke existing token: %w", err)
		}
	}
	// Save magic link token (15 minutes expiry)
	expiry := s.Auth.Config.AuthConfig.Tokens.MagicLinkTTL
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedToken, models.MakicLinkToken, expiry); err != nil {
		return fmt.Errorf("failed to save magic link token: %w", err)
	}

	s.Auth.Logger.Infof("Magic link sent to user %s", magicToken)

	// Create magic link URL
	magicURL := fmt.Sprintf("%s/verify-magic-link?token=%s&email=%s", s.Auth.Config.App.FrontendURL, magicToken, user.Email)

	// Send magic link email
	if s.Auth.Config.Email.CustomSender != nil {
		if err := s.Auth.Config.Email.CustomSender.SendMagicLinkEmail(ctx, *user, magicURL); err != nil {
			return fmt.Errorf("failed to send magic link email: %w", err)
		}
	}

	return nil
}

// VerifyMagicLink handles magic link verification
func (s *AuthService) VerifyMagicLink(ctx context.Context, req *dto.MagicLinkVerificationRequest) (*dto.LoginResponse, error) {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		// Don't reveal if user exists or not
		return nil, errors.New("user not found")
	}

	token, err := s.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(ctx, user.ID, models.MakicLinkToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	if token == nil {
		return nil, errors.New("token not found")
	}

	err = s.Auth.TokenManager.ValidateHashedToken(token.TokenValue, req.Token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Revoke the token

	err = s.Auth.Repository.GetTokenRepository().RevokeToken(ctx, token.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke token: %w", err)
	}

	accessToken, refreshToken, err := s.Auth.TokenManager.GenerateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}
	hashedRefreshToken, err := s.Auth.TokenManager.HashToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash refresh token: %w", err)
	}

	session := &models.Session{
		UserID:       user.ID,
		RefreshToken: hashedRefreshToken,
		ExpiresAt:    time.Now().Add(s.Auth.Config.AuthConfig.JWT.RefreshTokenTTL),
		IP:           req.Ip,
		UserAgent:    req.UserAgent,
		DeviceId:     &req.DeviceId,
		Location:     req.Location,
	}
	err = s.Auth.Repository.GetSessionRepository().CreateSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	response := dto.LoginResponse{
		SessionId: session.ID,
		Status:    http.StatusOK,
		Message:   "Login successful",
		User: dto.UserData{
			ID:            user.ID,
			Email:         user.Email,
			FirstName:     user.FirstName,
			LastName:      user.LastName,
			EmailVerified: user.EmailVerified,
		},
		Tokens: dto.TokenData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(s.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		},
	}

	return &response, nil
}
