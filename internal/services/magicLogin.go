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
	var user *models.User
	var magicToken string
	var hashedToken string
	var err error
	if req.Method == "phone" {
		user, err = s.Auth.Repository.GetUserRepository().GetUserByPhoneNumber(ctx, req.Phone)
		if err != nil {
			s.Auth.Logger.Errorf("failed to get user by phone number: %v", err)
			return fmt.Errorf("failed to get user by phone number")
		}
		if user == nil {
			s.Auth.Logger.Errorf("user not found")
			return fmt.Errorf("user not found")
		}
	} else if req.Method == "email" {
		user, err = s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
		if err != nil {
			s.Auth.Logger.Errorf("failed to get user by email: %v", err)
			return fmt.Errorf("failed to get user by email ")
		}
		if user == nil {
			s.Auth.Logger.Errorf("user not found")
			return fmt.Errorf("user not found")
		}
	}
	if req.Method == "phone" {
		magicToken, err = s.Auth.TokenManager.GenerateNumericOTP(6)
		if err != nil {
			s.Auth.Logger.Errorf("failed to generate magic link token: %v", err)
			return fmt.Errorf("failed to generate magic link token")
		}
		hashedToken, err = s.Auth.TokenManager.HashToken(magicToken)
		if err != nil {
			s.Auth.Logger.Errorf("failed to hash magic link token: %v", err)
			return fmt.Errorf("failed to hash magic link token")
		}
	} else {
		// Generate magic link token
		magicToken, err = s.Auth.TokenManager.GenerateRandomToken(32)
		if err != nil {
			s.Auth.Logger.Errorf("failed to generate magic link token: %v", err)
			return fmt.Errorf("failed to generate magic link token")
		}

		hashedToken, err = s.Auth.TokenManager.HashToken(magicToken)
		if err != nil {
			s.Auth.Logger.Errorf("failed to hash magic link token: %v", err)
			return fmt.Errorf("failed to hash magic link token")
		}

	}

	existingToken, err := s.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(ctx, user.ID, models.MakicLinkToken)
	if err != nil {
		s.Auth.Logger.Errorf("failed to get existing token: %v", err)
		return fmt.Errorf("failed to get existing token")
	}
	if existingToken != nil {
		err = s.Auth.Repository.GetTokenRepository().RevokeToken(ctx, existingToken.ID)
		if err != nil {
			s.Auth.Logger.Errorf("failed to revoke existing token: %v", err)
			return fmt.Errorf("failed to revoke existing token")
		}
	}
	// Save magic link token (15 minutes expiry)
	expiry := s.Auth.Config.AuthConfig.Tokens.MagicLinkTTL
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedToken, models.MakicLinkToken, expiry); err != nil {
		s.Auth.Logger.Errorf("failed to save magic link token: %v", err)
		return fmt.Errorf("failed to save magic link token")
	}

	s.Auth.Logger.Infof("Magic link sent to user %s", magicToken)

	if req.Method == "phone" {
		s.Auth.Logger.Infof("Magic link sent to user %s", magicToken)
		// Send magic link to user
		if err := s.Auth.Config.SMS.CustomSender.SendMagicLoginOTPSMS(ctx, *user, magicToken); err != nil {
			s.Auth.Logger.Errorf("failed to send magic link SMS: %v", err)
			return fmt.Errorf("failed to send magic link SMS")
		}
	} else {
		s.Auth.Logger.Infof("Magic link sent to user %s", magicToken)
		// Create magic link URL
		magicURL := fmt.Sprintf("%s/verify-magic-link?token=%s&email=%s", s.Auth.Config.App.FrontendURL, magicToken, user.Email)

		// Send magic link email
		if s.Auth.Config.Email.CustomSender != nil {
			if err := s.Auth.Config.Email.CustomSender.SendMagicLinkEmail(ctx, *user, magicURL); err != nil {
				return fmt.Errorf("failed to send magic link email: %w", err)
			}
		}
	}

	return nil
}

// VerifyMagicLink handles magic link verification
func (s *AuthService) VerifyMagicLink(ctx context.Context, req *dto.MagicLinkVerificationRequest) (*dto.LoginResponse, error) {
	var user *models.User
	var err error
	if req.Method == "phone" {
		user, err = s.Auth.Repository.GetUserRepository().GetUserByPhoneNumber(ctx, req.Phone)
		if err != nil {
			s.Auth.Logger.Errorf("failed to get user by phone number: %v", err)
			return nil, fmt.Errorf("failed to get user by phone number")
		}
		if user == nil {
			s.Auth.Logger.Errorf("user not found")
			return nil, fmt.Errorf("user not found")
		}
	} else if req.Method == "email" {
		user, err = s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
		if err != nil {
			s.Auth.Logger.Errorf("failed to get user by email: %v", err)
			return nil, fmt.Errorf("failed to get user by email")
		}
		if user == nil {
			return nil, fmt.Errorf("user not found")
		}
	}

	token, err := s.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(ctx, user.ID, models.MakicLinkToken)
	if err != nil {
		s.Auth.Logger.Errorf("failed to get token: %v", err)
		return nil, fmt.Errorf("failed to get token")
	}
	if token == nil {
		s.Auth.Logger.Errorf("token not found")
		return nil, errors.New("token not found")
	}

	err = s.Auth.TokenManager.ValidateHashedToken(token.TokenValue, req.Token)
	if err != nil {
		s.Auth.Logger.Errorf("invalid token: %v", err)
		return nil, fmt.Errorf("invalid token")
	}

	// Revoke the token

	err = s.Auth.Repository.GetTokenRepository().RevokeToken(ctx, token.ID)
	if err != nil {
		s.Auth.Logger.Errorf("failed to revoke token: %v", err)
		return nil, fmt.Errorf("failed to revoke token")
	}

	accessToken, refreshToken, err := s.Auth.TokenManager.GenerateTokens(user)
	if err != nil {
		s.Auth.Logger.Errorf("failed to generate tokens: %v", err)
		return nil, fmt.Errorf("failed to generate tokens")
	}
	hashedRefreshToken, err := s.Auth.TokenManager.HashToken(refreshToken)
	if err != nil {
		s.Auth.Logger.Errorf("failed to hash refresh token: %v", err)
		return nil, fmt.Errorf("failed to hash refresh token")
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
		s.Auth.Logger.Errorf("failed to create session: %v", err)
		return nil, fmt.Errorf("failed to create session")
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
