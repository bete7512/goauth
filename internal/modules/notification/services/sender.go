package services

import (
	"context"
	"fmt"

	coreModels "github.com/bete7512/goauth/internal/modules/core/models"
)

// SendWelcomeEmail sends a welcome email after signup
func (s *NotificationService) sendWelcomeEmail(ctx context.Context, email, userName string) error {
	tmpl, ok := s.templates["welcome"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"AppName":  s.config.AppName,
		"UserName": userName,
	}

	if tmpl.SendEmail && s.emailSender != nil {
		return s.sendTemplatedEmail(ctx, &tmpl, email, data)
	}

	return nil
}

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

// SendTwoFactorCode sends 2FA code via email or SMS
func (s *NotificationService) sendTwoFactorCode(ctx context.Context, email, phoneNumber, code string, expiryTime string) error {
	tmpl, ok := s.templates["two_factor_code"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"Code":       code,
		"ExpiryTime": expiryTime,
	}

	var emailErr, smsErr error

	// Send via email
	if tmpl.SendEmail && s.emailSender != nil && email != "" {
		emailErr = s.sendTemplatedEmail(ctx, &tmpl, email, data)
	}

	// Send via SMS
	if tmpl.SendSMS && s.smsSender != nil && phoneNumber != "" {
		smsErr = s.sendTemplatedSMS(ctx, &tmpl, phoneNumber, data)
	}

	// Return error only if both failed
	if emailErr != nil && smsErr != nil {
		return fmt.Errorf("failed to send 2FA code via email (%v) and SMS (%v)", emailErr, smsErr)
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

// SendLoginAlert sends login alert notification
func (s *NotificationService) sendLoginAlert(ctx context.Context, email, userName, ipAddress, timestamp string) error {
	tmpl, ok := s.templates["login_alert"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"UserName":  userName,
		"IPAddress": ipAddress,
		"Timestamp": timestamp,
	}

	if tmpl.SendEmail && s.emailSender != nil {
		return s.sendTemplatedEmail(ctx, &tmpl, email, data)
	}

	return nil
}

// SendPasswordChangedAlert sends password changed notification
func (s *NotificationService) sendPasswordChangedAlert(ctx context.Context, email, userName, timestamp string) error {
	tmpl, ok := s.templates["password_changed"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"UserName":    userName,
		"Timestamp":   timestamp,
		"SupportLink": s.config.SupportLink,
	}

	if tmpl.SendEmail && s.emailSender != nil {
		return s.sendTemplatedEmail(ctx, &tmpl, email, data)
	}

	return nil
}
