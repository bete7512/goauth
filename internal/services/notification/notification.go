package notification_service

import (
	"context"
	"fmt"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

func (s *NotificationService) SendVerificationEmail(ctx context.Context, user *models.User, redirectURL string) *types.GoAuthError {
	if s.config.Email.CustomSender == nil {
		msg := "email sender not configured"
		return types.NewConfigurationError(&msg)
	}

	if err := s.config.Email.CustomSender.SendVerificationEmail(ctx, *user, redirectURL); err != nil {
		return types.NewInternalError(err.Error())
	}

	return nil
}

// SendWelcomeEmail sends welcome email
func (s *NotificationService) SendWelcomeEmail(ctx context.Context, user *models.User) *types.GoAuthError {
	if s.config.Email.CustomSender == nil {
		msg := "email sender not configured"
		return types.NewConfigurationError(&msg)
	}

	if err := s.config.Email.CustomSender.SendWelcomeEmail(ctx, *user); err != nil {
		return types.NewInternalError(err.Error())
	}

	return nil
}

// SendForgetPasswordEmail sends password reset email
func (s *NotificationService) SendForgetPasswordEmail(ctx context.Context, user *models.User, redirectURL string) *types.GoAuthError {
	if s.config.Email.CustomSender == nil {
		msg := "email sender not configured"
		return types.NewConfigurationError(&msg)
	}

	if err := s.config.Email.CustomSender.SendForgetPasswordEmail(ctx, *user, redirectURL); err != nil {
		return types.NewInternalError(err.Error())
	}

	return nil
}

// SendTwoFactorEmail sends two-factor authentication email
func (s *NotificationService) SendTwoFactorEmail(ctx context.Context, user *models.User, code string) *types.GoAuthError {
	if s.config.Email.CustomSender == nil {
		msg := "email sender not configured"
		return types.NewConfigurationError(&msg)
	}

	if err := s.config.Email.CustomSender.SendTwoFactorEmail(ctx, *user, code); err != nil {
		return types.NewInternalError(err.Error())
	}

	return nil
}

// SendMagicLinkEmail sends magic link email
func (s *NotificationService) SendMagicLinkEmail(ctx context.Context, user *models.User, redirectURL string) *types.GoAuthError {
	if s.config.Email.CustomSender == nil {
		msg := "email sender not configured"
		return types.NewConfigurationError(&msg)
	}

	if err := s.config.Email.CustomSender.SendMagicLinkEmail(ctx, *user, redirectURL); err != nil {
		return types.NewInternalError(err.Error())
	}

	return nil
}

// SendInvitationEmail sends invitation email
func (s *NotificationService) SendInvitationEmail(ctx context.Context, user *models.User, invitationURL string, invitedBy string) *types.GoAuthError {
	if s.config.Email.CustomSender == nil {
		msg := "email sender not configured"
		return types.NewConfigurationError(&msg)
	}

	if err := s.config.Email.CustomSender.SendInvitationEmail(ctx, *user, invitationURL); err != nil {
		return types.NewInternalError(err.Error())
	}

	return nil
}

// SendVerificationSMS sends SMS verification
func (s *NotificationService) SendVerificationSMS(ctx context.Context, user *models.User, code string) *types.GoAuthError {
	if s.config.SMS.CustomSender == nil {
		msg := "SMS sender not configured"
		return types.NewConfigurationError(&msg)
	}

	if err := s.config.SMS.CustomSender.SendVerificationSMS(ctx, *user, code); err != nil {
		return types.NewCustomError(err.Error())
	}

	return nil
}

// setupEmailVerification sets up email verification for a user
func (s *NotificationService) sendEmailVerification(ctx context.Context, user *models.User) *types.GoAuthError {

	// Generate verification token
	verificationToken, err := s.tokenMgr.GenerateRandomToken(32)
	if err != nil {
		s.logger.Errorf("failed to generate verification token: %v", err)
		return types.NewInternalError(err.Error())
	}

	hashedVerificationToken, err := s.tokenMgr.HashToken(verificationToken)
	if err != nil {
		s.logger.Errorf("failed to hash verification token: %v", err)
		return types.NewInternalError(err.Error())
	}
	if user.EmailVerified != nil && *user.EmailVerified {
		s.logger.Errorf("email already verified")
		return types.NewEmailAlreadyVerifiedError()
	}

	existingToken, err := s.tokenRepo.GetActiveTokenByUserIdAndType(ctx, user.ID, models.EmailVerificationToken)
	if err != nil {
		s.logger.Errorf("failed to get active token by user id and type: %v", err)
		return types.NewInternalError(err.Error())
	}
	if existingToken != nil {
		err = s.tokenRepo.RevokeToken(ctx, existingToken.ID)
		if err != nil {
			s.logger.Errorf("failed to revoke token: %v", err)
			return types.NewInternalError(err.Error())
		}
	}

	// Save verification token
	if err := s.tokenRepo.SaveToken(ctx, user.ID, hashedVerificationToken, models.EmailVerificationToken, s.config.AuthConfig.Tokens.EmailVerificationTTL); err != nil {
		s.logger.Errorf("failed to save verification token: %v", err)
		return types.NewInternalError(err.Error())
	}

	// Send verification email asynchronously
	verificationURL := fmt.Sprintf("%s?token=%s&email=%s",
		s.config.AuthConfig.Methods.EmailVerification.VerificationURL,
		verificationToken,
		user.Email)

	s.config.WorkerPool.Submit(func() {
		if err := s.config.Email.CustomSender.SendVerificationEmail(ctx, *user, verificationURL); err != nil {
			s.logger.Errorf("failed to send verification email to user %s: %v", user.Email, err)
		}
	})

	return nil
}

// setupPhoneVerification sets up phone verification for a user
func (s *NotificationService) sendPhoneVerification(ctx context.Context, user *models.User) *types.GoAuthError {
	if s.config.SMS.CustomSender == nil {
		msg := "SMS sender not configured"
		return types.NewConfigurationError(&msg)
	}

	if user != nil && user.PhoneVerified != nil && *user.PhoneVerified {
		s.logger.Errorf("phone already verified")
		return types.NewPhoneAlreadyVerifiedError()
	}

	// Generate OTP
	otp, err := s.tokenMgr.GenerateNumericOTP(6)
	if err != nil {
		s.logger.Errorf("failed to generate OTP: %v", err)
		return types.NewInternalError(err.Error())
	}

	hashedOTP, err := s.tokenMgr.HashToken(otp)
	if err != nil {
		s.logger.Errorf("failed to hash OTP: %v", err)
		return types.NewInternalError(err.Error())
	}

	existingToken, err := s.tokenRepo.GetActiveTokenByUserIdAndType(ctx, user.ID, models.PhoneVerificationToken)
	if err != nil {
		s.logger.Errorf("failed to get active token by user id and type: %v", err)
		return types.NewInternalError(err.Error())
	}
	if existingToken != nil {
		err = s.tokenRepo.RevokeToken(ctx, existingToken.ID)
		if err != nil {
			s.logger.Errorf("failed to revoke token: %v", err)
			return types.NewInternalError(err.Error())
		}
	}
	// Save verification token
	if err := s.tokenRepo.SaveToken(ctx, user.ID, hashedOTP, models.PhoneVerificationToken, s.config.AuthConfig.Tokens.PhoneVerificationTTL); err != nil {
		return types.NewInternalError(err.Error())
	}

	s.logger.Infof("Sending verification SMS to user %s: %s", *user.PhoneNumber, otp)
	s.config.WorkerPool.Submit(func() {
		if err := s.config.SMS.CustomSender.SendTwoFactorSMS(ctx, *user, otp); err != nil {
			s.logger.Errorf("failed to send verification SMS to user %s: %v", *user.PhoneNumber, err)
		}
	})

	return nil
}
