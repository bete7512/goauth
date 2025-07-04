package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

// SendEmailVerification sends email verification
func (s *AuthService) SendEmailVerification(ctx context.Context, email string) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("user not found")
		}
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user.EmailVerified != nil && *user.EmailVerified {
		return errors.New("email already verified")
	}

	// s.sendEmailVerification(ctx, user)
	s.Auth.WorkerPool.Submit(func() {
		if err := s.sendEmailVerification(ctx, user); err != nil {
			s.Auth.Logger.Errorf("Failed to send email verification: %v", err)
		}
	})

	return nil
}

// VerifyEmail verifies email address
func (s *AuthService) VerifyEmail(ctx context.Context, req *dto.EmailVerificationRequest) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	token, err := s.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(ctx, user.ID, models.EmailVerificationToken)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	if token == nil {
		return fmt.Errorf("token not found")
	}

	err = s.Auth.TokenManager.ValidateHashedToken(token.TokenValue, req.Token)
	if err != nil {
		return fmt.Errorf("failed to verify token: %w", err)
	}

	err = s.Auth.Repository.GetTokenRepository().RevokeToken(ctx, token.ID)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	active := true
	verified := true
	emailVerifiedAt := time.Now()
	user.EmailVerified = &verified
	user.EmailVerifiedAt = &emailVerifiedAt
	user.Active = &active
	err = s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// SendPhoneVerification sends phone verification
func (s *AuthService) SendPhoneVerification(ctx context.Context, phoneNumber string) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByPhoneNumber(ctx, phoneNumber)
	if err != nil || user == nil {
		return errors.New("user not found")
	}
	if user.PhoneVerified != nil && *user.PhoneVerified {
		return errors.New("phone already verified")
	}

	s.Auth.WorkerPool.Submit(func() {
		if err := s.sendPhoneVerification(ctx, user); err != nil {
			s.Auth.Logger.Errorf("Failed to send phone verification: %v", err)
		}
	})

	return nil
}

// VerifyPhone verifies phone number
func (s *AuthService) VerifyPhone(ctx context.Context, req *dto.PhoneVerificationRequest) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByPhoneNumber(ctx, req.PhoneNumber)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	token, err := s.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(ctx, user.ID, models.PhoneVerificationToken)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	if token == nil {
		return fmt.Errorf("token not found")
	}

	err = s.Auth.TokenManager.ValidateHashedToken(token.TokenValue, req.Code)
	if err != nil {
		return fmt.Errorf("failed to verify token: %w", err)
	}

	err = s.Auth.Repository.GetTokenRepository().RevokeToken(ctx, token.ID)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	active := true
	verified := true
	user.PhoneVerified = &verified
	phoneVerifiedAt := time.Now()
	user.PhoneVerifiedAt = &phoneVerifiedAt
	user.Active = &active

	err = s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	s.Auth.Logger.Infof("Phone verified for user %s", user.ID)

	return nil
}

// SendActionConfirmation sends action confirmation
func (s *AuthService) SendActionConfirmation(ctx context.Context, userID string, req *dto.ActionConfirmationRequest) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// Generate confirmation token
	confirmationToken, err := s.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate confirmation token: %w", err)
	}

	hashedToken, err := s.Auth.TokenManager.HashToken(confirmationToken)
	if err != nil {
		return fmt.Errorf("failed to hash confirmation token: %w", err)
	}

	// Save confirmation token (1 hour expiry)
	expiry := time.Hour
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedToken, models.ActionConfirmationToken, expiry); err != nil {
		return fmt.Errorf("failed to save confirmation token: %w", err)
	}

	// Create confirmation URL
	confirmationURL := fmt.Sprintf("%s/action/verify?token=%s&action=%s", s.Auth.Config.App.FrontendURL, confirmationToken, req.ActionType)

	// Send confirmation email
	if s.Auth.Config.Email.CustomSender != nil {
		if err := s.Auth.Config.Email.CustomSender.SendVerificationEmail(ctx, *user, confirmationURL); err != nil {
			return fmt.Errorf("failed to send confirmation email: %w", err)
		}
	}

	return nil
}

// VerifyActionConfirmation verifies action confirmation
func (s *AuthService) VerifyActionConfirmation(ctx context.Context, userID string, req *dto.ActionConfirmationVerificationRequest) error {
	// TODO: Implement token verification logic
	// For now, we'll assume the token is valid

	// TODO: Execute the confirmed action
	// This would require finding the user by token and executing the requested action

	return errors.New("not implemented")
}
