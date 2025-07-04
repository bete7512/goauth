package services

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
)

// ForgotPassword handles password reset request
func (s *AuthService) ForgotPassword(ctx context.Context, req *dto.ForgotPasswordRequest) error {
	// Get user by email
	user, err := s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		// Don't reveal if user exists or not
		return nil
	}

	// Generate reset token
	resetToken, err := s.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	hashedToken, err := s.Auth.TokenManager.HashToken(resetToken)
	if err != nil {
		return fmt.Errorf("failed to hash reset token: %w", err)
	}

	// Save reset token (1 hour expiry)
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedToken, models.PasswordResetToken, time.Hour); err != nil {
		return fmt.Errorf("failed to save reset token: %w", err)
	}

	// Create reset URL
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.Auth.Config.App.FrontendURL, resetToken)

	// Send reset email
	if s.Auth.Config.Email.CustomSender != nil {
		if err := s.Auth.Config.Email.CustomSender.SendForgetPasswordEmail(ctx, *user, resetURL); err != nil {
			return fmt.Errorf("failed to send reset email: %w", err)
		}
	}

	return nil
}
