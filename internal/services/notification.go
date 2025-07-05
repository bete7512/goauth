package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/bete7512/goauth/pkg/models"
)

// setupEmailVerification sets up email verification for a user
func (s *AuthService) sendEmailVerification(ctx context.Context, user *models.User) error {

	// Generate verification token
	verificationToken, err := s.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		s.Auth.Logger.Error("Failed to generate verification token")
		return err
	}

	hashedVerificationToken, err := s.Auth.TokenManager.HashToken(verificationToken)
	if err != nil {
		s.Auth.Logger.Error("Failed to hash verification token")
		return err
	}
	if user.EmailVerified != nil && *user.EmailVerified {
		s.Auth.Logger.Info("User %s already verified", user.Email)
		return nil
	}

	existingToken, err := s.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(ctx, user.ID, models.EmailVerificationToken)
	if err != nil {
		s.Auth.Logger.Error("Failed to get verification token")
		return err
	}
	if existingToken != nil {
		err = s.Auth.Repository.GetTokenRepository().RevokeToken(ctx, existingToken.ID)
		if err != nil {
			s.Auth.Logger.Error("Failed to revoke existing verification token")
			return err
		}
	}

	// Save verification token
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedVerificationToken, models.EmailVerificationToken, s.Auth.Config.AuthConfig.Tokens.EmailVerificationTTL); err != nil {
		s.Auth.Logger.Error("Failed to save verification token")
		return err
	}

	// Send verification email asynchronously
	verificationURL := fmt.Sprintf("%s?token=%s&email=%s",
		s.Auth.Config.AuthConfig.Methods.EmailVerification.VerificationURL,
		verificationToken,
		user.Email)

	s.Auth.WorkerPool.Submit(func() {
		s.Auth.Logger.Info("Sending verification email to user %s", user.Email)
		if err := s.Auth.Config.Email.CustomSender.SendVerificationEmail(ctx, *user, verificationURL); err != nil {
			s.Auth.Logger.Errorf("Failed to send verification email to user %s: %v", user.Email, err)
		}
	})

	return nil
}

// setupPhoneVerification sets up phone verification for a user
func (s *AuthService) sendPhoneVerification(ctx context.Context, user *models.User) error {
	if s.Auth.Config.SMS.CustomSender == nil {
		s.Auth.Logger.Error("SMS sender not configured")
	}

	if user != nil && user.PhoneVerified != nil && *user.PhoneVerified {
		s.Auth.Logger.Info("User %s already verified", *user.PhoneNumber)
		return errors.New("user already verified")
	}

	// Generate OTP
	otp, err := s.Auth.TokenManager.GenerateNumericOTP(6)
	if err != nil {
		s.Auth.Logger.Error("Failed to generate OTP")
		return err
	}

	hashedOTP, err := s.Auth.TokenManager.HashToken(otp)
	if err != nil {
		s.Auth.Logger.Error("Failed to hash OTP")
		return err
	}

	existingToken, err := s.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(ctx, user.ID, models.PhoneVerificationToken)
	if err != nil {
		s.Auth.Logger.Error("Failed to get verification token")
		return err
	}
	if existingToken != nil {
		err = s.Auth.Repository.GetTokenRepository().RevokeToken(ctx, existingToken.ID)
		if err != nil {
			s.Auth.Logger.Error("Failed to revoke existing verification token")
			return err
		}
	}
	// Save verification token
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedOTP, models.PhoneVerificationToken, s.Auth.Config.AuthConfig.Tokens.PhoneVerificationTTL); err != nil {
		s.Auth.Logger.Error("Failed to save OTP")
		return err
	}

	s.Auth.Logger.Infof("Sending verification SMS to user %s: %s", *user.PhoneNumber, otp)
	// Send verification SMS asynchronously (fixed: removed duplicate sending)
	s.Auth.WorkerPool.Submit(func() {
		if err := s.Auth.Config.SMS.CustomSender.SendTwoFactorSMS(ctx, *user, otp); err != nil {
			s.Auth.Logger.Errorf("Failed to send verification SMS to user %s: %v", *user.PhoneNumber, err)
		}
	})

	return nil
}
