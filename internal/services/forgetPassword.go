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
	var user *models.User

	var resetToken string
	var hashedToken string
	var err error
	if req.Method == "email" {
		user, err = s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
		if err != nil {
			s.Auth.Logger.Errorf("failed to get user by email: %v", err)
			return fmt.Errorf("failed to get user by email")
		}
		if user == nil {
			s.Auth.Logger.Errorf("user not found")
			return fmt.Errorf("user not found")
		}
	} else if req.Method == "phone" {
		user, err = s.Auth.Repository.GetUserRepository().GetUserByPhoneNumber(ctx, req.Phone)
		if err != nil {
			s.Auth.Logger.Errorf("failed to get user by phone number: %v", err)
			return fmt.Errorf("failed to get user by phone number")
		}
		if user == nil {
			s.Auth.Logger.Errorf("user not found")
			return fmt.Errorf("user not found")
		}
	}

	if req.Method == "email" {
		// Generate reset token
		resetToken, err = s.Auth.TokenManager.GenerateRandomToken(32)
		if err != nil {
			return fmt.Errorf("failed to generate reset token: %w", err)
		}

		hashedToken, err = s.Auth.TokenManager.HashToken(resetToken)
		if err != nil {
			return fmt.Errorf("failed to hash reset token: %w", err)
		}

		// Create reset URL
		resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.Auth.Config.App.FrontendURL, resetToken)

		// Send reset email
		if s.Auth.Config.Email.CustomSender != nil {
			s.Auth.Logger.Infof("sending reset email to user %s %s", user.ID, resetToken)
			if err := s.Auth.Config.Email.CustomSender.SendForgetPasswordEmail(ctx, *user, resetURL); err != nil {
				return fmt.Errorf("failed to send reset email: %w", err)
			}
		} else {
			s.Auth.Logger.Errorf("no email sender configured")
		}
	} else if req.Method == "phone" {
		// Generate reset token
		resetToken, err = s.Auth.TokenManager.GenerateNumericOTP(6)
		if err != nil {
			return fmt.Errorf("failed to generate reset token: %w", err)
		}
		hashedToken, err = s.Auth.TokenManager.HashToken(resetToken)
		if err != nil {
			return fmt.Errorf("failed to hash reset token: %w", err)
		}

		// Send reset SMS
		if s.Auth.Config.SMS.CustomSender != nil {
			s.Auth.Logger.Infof("sending reset SMS to user %s %s", user.ID, resetToken)
			if err := s.Auth.Config.SMS.CustomSender.SendForgetPasswordSMS(ctx, *user, resetToken); err != nil {
				return fmt.Errorf("failed to send reset SMS: %w", err)
			}
		} else {
			s.Auth.Logger.Errorf("no SMS sender configured")
		}

	}
	// save token to db

	err = s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedToken, models.ForgotPasswordToken, time.Hour)
	if err != nil {
		return fmt.Errorf("failed to save reset token: %w", err)
	}

	return nil
}

// ResetPassword handles password reset
func (s *AuthService) ResetPassword(ctx context.Context, req *dto.ResetPasswordRequest) error {
	var user *models.User
	var err error
	if req.Method == "email" {
		user, err = s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
		if err != nil {
			s.Auth.Logger.Errorf("failed to get user by email: %v", err)
			return fmt.Errorf("failed to get user by email")
		}
	} else if req.Method == "phone" {
		user, err = s.Auth.Repository.GetUserRepository().GetUserByPhoneNumber(ctx, req.Phone)
		if err != nil {
			s.Auth.Logger.Errorf("failed to get user by phone number: %v", err)
			return fmt.Errorf("failed to get user by phone number")
		}
	}
	if user == nil {
		s.Auth.Logger.Errorf("user not found")
		return fmt.Errorf("user not found")
	}

	// Verify token
	token, err := s.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(ctx, user.ID, models.ForgotPasswordToken)
	if err != nil {
		s.Auth.Logger.Errorf("failed to get active token by user id and type: %v", err)
		return fmt.Errorf("failed to get active token by user id and type")
	}
	if token == nil {
		s.Auth.Logger.Errorf("token not found")
		return fmt.Errorf("token not found")
	}

	// Verify token
	if err := s.Auth.TokenManager.ValidateHashedToken(token.TokenValue, req.Token); err != nil {
		s.Auth.Logger.Errorf("failed to validate token: %v", err)
		return fmt.Errorf("failed to validate token")
	}

	// Update user password
	hashedPassword, err := s.Auth.TokenManager.HashPassword(req.NewPassword)
	if err != nil {
		s.Auth.Logger.Errorf("failed to hash password: %v", err)
		return fmt.Errorf("failed to hash password")
	}
	user.Password = hashedPassword

	// Revoke token
	if err := s.Auth.Repository.GetTokenRepository().RevokeToken(ctx, token.ID); err != nil {
		s.Auth.Logger.Errorf("failed to revoke token: %v", err)
		return fmt.Errorf("failed to revoke token")
	}

	// Update user
	if err := s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user); err != nil {
		s.Auth.Logger.Errorf("failed to update user: %v", err)
		return fmt.Errorf("failed to update user")
	}

	return nil
}
