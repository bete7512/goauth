package services

import (
	"context"

	coreModels "github.com/bete7512/goauth/internal/modules/core/models"
)

// SendPasswordResetEmail sends password reset email
func (s *NotificationService) sendPasswordResetEmail(ctx context.Context, email, userName, resetLink, code string, expiryTime string) error {
	tmpl, ok := s.templates["password_reset"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"AppName":    s.config.AppName,
		"UserName":   userName,
		"ResetLink":  resetLink,
		"Code":       code,
		"ExpiryTime": expiryTime,
	}

	if tmpl.SendEmail && s.emailSender != nil {
		return s.sendTemplatedEmail(ctx, &tmpl, email, data)
	}

	return nil
}

// SendPasswordResetSMS sends password reset SMS
func (s *NotificationService) sendPasswordResetSMS(ctx context.Context, phoneNumber, code, expiryTime string) error {
	tmpl, ok := s.templates["password_reset"]
	if !ok || !tmpl.Enabled || !tmpl.SendSMS {
		return nil
	}

	if s.smsSender == nil {
		return nil
	}

	data := map[string]interface{}{
		"AppName":    s.config.AppName,
		"Code":       code,
		"ExpiryTime": expiryTime,
	}

	return s.sendTemplatedSMS(ctx, &tmpl, phoneNumber, data)
}

// SendEmailVerification sends email verification
func (s *NotificationService) sendEmailVerification(ctx context.Context, email, userName, verificationLink string) error {
	tmpl, ok := s.templates["email_verification"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"AppName":          s.config.AppName,
		"UserName":         userName,
		"VerificationLink": verificationLink,
	}

	if tmpl.SendEmail && s.emailSender != nil {
		return s.sendTemplatedEmail(ctx, &tmpl, email, data)
	}

	return nil
}

func (s *NotificationService) sendPhoneVerification(ctx context.Context, user coreModels.User, code string, expiryTime string) error {
	tmpl, ok := s.templates["phone_verification"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"AppName":    s.config.AppName,
		"UserName":   user.Name,
		"Code":       code,
		"ExpiryTime": expiryTime,
	}

	if tmpl.SendSMS && s.smsSender != nil {
		return s.sendTemplatedSMS(ctx, &tmpl, user.PhoneNumber, data)
	}

	return nil
}
