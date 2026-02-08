package services

import (
	"context"
)

// SendPasswordResetEmail renders the password reset template and delivers via email.
func (s *notificationService) SendPasswordResetEmail(ctx context.Context, email, userName, resetLink, code, expiryTime string) error {
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

// SendPasswordResetSMS renders the password reset template and delivers via SMS.
func (s *notificationService) SendPasswordResetSMS(ctx context.Context, phoneNumber, code, expiryTime string) error {
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

// SendEmailVerification renders the email verification template and delivers.
func (s *notificationService) SendEmailVerification(ctx context.Context, email, userName, verificationLink string) error {
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

// SendPhoneVerification renders the phone verification template and delivers via SMS.
func (s *notificationService) SendPhoneVerification(ctx context.Context, phoneNumber, userName, code, expiryTime string) error {
	tmpl, ok := s.templates["phone_verification"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"AppName":    s.config.AppName,
		"UserName":   userName,
		"Code":       code,
		"ExpiryTime": expiryTime,
	}

	if tmpl.SendSMS && s.smsSender != nil {
		return s.sendTemplatedSMS(ctx, &tmpl, phoneNumber, data)
	}

	return nil
}
