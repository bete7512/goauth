package handlers

import (
	"context"
	"errors"
	"fmt"

	responseErrors "github.com/bete7512/goauth/internal/api/handlers/errors"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

// setupEmailVerification sets up email verification for a user
func (h *AuthRoutes) setupEmailVerification(ctx context.Context, user *types.User) error {
	if h.Auth.Config.Email.Sender.CustomSender == nil {
		return errors.New("email sender not configured")
	}

	// Generate verification token
	verificationToken, err := h.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate verification token: %w", err)
	}

	hashedVerificationToken, err := h.Auth.TokenManager.HashToken(verificationToken)
	if err != nil {
		return fmt.Errorf("failed to hash verification token: %w", err)
	}

	// Save verification token
	if err := h.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedVerificationToken, types.EmailVerificationToken, h.Auth.Config.AuthConfig.Tokens.EmailVerificationTTL); err != nil {
		return fmt.Errorf("failed to save verification token: %w", err)
	}

	// Send verification email asynchronously
	verificationURL := fmt.Sprintf("%s?token=%s&email=%s",
		h.Auth.Config.AuthConfig.Methods.EmailVerification.VerificationURL,
		verificationToken,
		user.Email)

	h.Auth.Logger.Infof("Sending verification email to user %d: %s", user.ID, verificationToken)
	h.Auth.WorkerPool.Submit(func() {
		if err := h.Auth.Config.Email.Sender.CustomSender.SendVerificationEmail(context.Background(), *user, verificationURL); err != nil {
			h.Auth.Logger.Errorf("Failed to send verification email to user %d: %v", user.ID, err)
		}
	})

	return nil
}

// setupPhoneVerification sets up phone verification for a user
func (h *AuthRoutes) setupPhoneVerification(ctx context.Context, user *types.User) error {
	if h.Auth.Config.SMS.CustomSender == nil {
		return errors.New("SMS sender not configured")
	}

	// Generate OTP
	otp, err := h.Auth.TokenManager.GenerateNumericOTP(6)
	if err != nil {
		return fmt.Errorf("failed to generate verification OTP: %w", err)
	}

	hashedOTP, err := h.Auth.TokenManager.HashToken(otp)
	if err != nil {
		return fmt.Errorf("failed to hash verification OTP: %w", err)
	}

	// Save verification token
	if err := h.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedOTP, types.PhoneVerificationToken, h.Auth.Config.AuthConfig.Tokens.PhoneVerificationTTL); err != nil {
		return fmt.Errorf("failed to save verification OTP: %w", err)
	}

	h.Auth.Logger.Infof("Sending verification SMS to user %d: %s", user.ID, otp)
	// Send verification SMS asynchronously (fixed: removed duplicate sending)
	h.Auth.WorkerPool.Submit(func() {
		if err := h.Auth.Config.SMS.CustomSender.SendTwoFactorSMS(context.Background(), *user, otp); err != nil {
			h.Auth.Logger.Errorf("Failed to send verification SMS to user %d: %v", user.ID, err)
		}
	})

	return nil
}

// getUserByEmail retrieves user by email with proper error handling
func (h *AuthRoutes) getUserByEmail(ctx context.Context, email string) (*types.User, error) {
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New(responseErrors.ErrUserNotFound)
		}
		return nil, errors.New(responseErrors.ErrInternalError)
	}

	if user == nil {
		return nil, errors.New(responseErrors.ErrUserNotFound)
	}

	return user, nil
}

// getUserByPhoneNumber retrieves user by phone number with proper error handling
func (h *AuthRoutes) getUserByPhoneNumber(ctx context.Context, phoneNumber string) (*types.User, error) {
	// Try to get authenticated user first
	user, err := h.Auth.Repository.GetUserRepository().GetUserByPhoneNumber(ctx, phoneNumber)
	if err != nil {
		return nil, errors.New(responseErrors.ErrUserNotFound)
	}

	if user == nil {
		return nil, errors.New(responseErrors.ErrUserNotFound)
	}

	return user, nil
}
