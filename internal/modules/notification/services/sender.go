package services

import (
	"context"
)

// SendPasswordResetEmail renders the password reset template and delivers via email.
func (s *notificationService) SendPasswordResetEmail(ctx context.Context, email, userName, resetLink, code, expiryTime string) error {
	tmpl, ok := s.emailTemplates["password_reset"]
	if !ok {
		return nil
	}

	if s.emailSender == nil {
		return nil
	}

	data := map[string]interface{}{
		"UserName":   userName,
		"ResetLink":  resetLink,
		"Code":       code,
		"ExpiryTime": expiryTime,
	}

	return s.sendTemplatedEmail(ctx, &tmpl, email, data)
}

// SendPasswordResetSMS renders the password reset template and delivers via SMS.
func (s *notificationService) SendPasswordResetSMS(ctx context.Context, phoneNumber, code, expiryTime string) error {
	tmpl, ok := s.smsTemplates["password_reset"]
	if !ok {
		return nil
	}

	if s.smsSender == nil {
		return nil
	}

	data := map[string]interface{}{
		"Code":       code,
		"ExpiryTime": expiryTime,
	}

	return s.sendTemplatedSMS(ctx, &tmpl, phoneNumber, data)
}

// SendEmailVerification renders the email verification template and delivers.
func (s *notificationService) SendEmailVerification(ctx context.Context, email, userName, verificationLink string) error {
	tmpl, ok := s.emailTemplates["email_verification"]
	if !ok {
		return nil
	}

	if s.emailSender == nil {
		return nil
	}

	data := map[string]interface{}{
		"UserName":         userName,
		"VerificationLink": verificationLink,
	}

	return s.sendTemplatedEmail(ctx, &tmpl, email, data)
}

// SendPhoneVerification renders the phone verification template and delivers via SMS.
func (s *notificationService) SendPhoneVerification(ctx context.Context, phoneNumber, userName, code, expiryTime string) error {
	tmpl, ok := s.smsTemplates["phone_verification"]
	if !ok {
		return nil
	}

	if s.smsSender == nil {
		return nil
	}

	data := map[string]interface{}{
		"UserName":   userName,
		"Code":       code,
		"ExpiryTime": expiryTime,
	}

	return s.sendTemplatedSMS(ctx, &tmpl, phoneNumber, data)
}
