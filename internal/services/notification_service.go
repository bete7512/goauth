package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/bete7512/goauth/pkg/models"
)

func (s *AuthService) SendVerificationEmail(ctx context.Context, user *models.User, redirectURL string) error {
	if s.Auth.Config.Email.CustomSender == nil {
		return errors.New("email sender not configured")
	}

	if err := s.Auth.Config.Email.CustomSender.SendVerificationEmail(ctx, *user, redirectURL); err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	return nil
}

// SendWelcomeEmail sends welcome email
func (s *AuthService) SendWelcomeEmail(ctx context.Context, user *models.User) error {
	if s.Auth.Config.Email.CustomSender == nil {
		return errors.New("email sender not configured")
	}

	if err := s.Auth.Config.Email.CustomSender.SendWelcomeEmail(ctx, *user); err != nil {
		return fmt.Errorf("failed to send welcome email: %w", err)
	}

	return nil
}

// SendForgetPasswordEmail sends password reset email
func (s *AuthService) SendForgetPasswordEmail(ctx context.Context, user *models.User, redirectURL string) error {
	if s.Auth.Config.Email.CustomSender == nil {
		return errors.New("email sender not configured")
	}

	if err := s.Auth.Config.Email.CustomSender.SendForgetPasswordEmail(ctx, *user, redirectURL); err != nil {
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	return nil
}

// SendTwoFactorEmail sends two-factor authentication email
func (s *AuthService) SendTwoFactorEmail(ctx context.Context, user *models.User, code string) error {
	if s.Auth.Config.Email.CustomSender == nil {
		return errors.New("email sender not configured")
	}

	if err := s.Auth.Config.Email.CustomSender.SendTwoFactorEmail(ctx, *user, code); err != nil {
		return fmt.Errorf("failed to send two-factor email: %w", err)
	}

	return nil
}

// SendMagicLinkEmail sends magic link email
func (s *AuthService) SendMagicLinkEmail(ctx context.Context, user *models.User, redirectURL string) error {
	if s.Auth.Config.Email.CustomSender == nil {
		return errors.New("email sender not configured")
	}

	if err := s.Auth.Config.Email.CustomSender.SendMagicLinkEmail(ctx, *user, redirectURL); err != nil {
		return fmt.Errorf("failed to send magic link email: %w", err)
	}

	return nil
}

// SendInvitationEmail sends invitation email
func (s *AuthService) SendInvitationEmail(ctx context.Context, user *models.User, invitationURL string, invitedBy string) error {
	if s.Auth.Config.Email.CustomSender == nil {
		return errors.New("email sender not configured")
	}

	if err := s.Auth.Config.Email.CustomSender.SendInvitationEmail(ctx, *user, invitationURL); err != nil {
		return fmt.Errorf("failed to send invitation email: %w", err)
	}

	return nil
}

// SendVerificationSMS sends SMS verification
func (s *AuthService) SendVerificationSMS(ctx context.Context, user *models.User, code string) error {
	if s.Auth.Config.SMS.CustomSender == nil {
		return errors.New("SMS sender not configured")
	}

	if err := s.Auth.Config.SMS.CustomSender.SendVerificationSMS(ctx, *user, code); err != nil {
		return fmt.Errorf("failed to send verification SMS: %w", err)
	}

	return nil
}
