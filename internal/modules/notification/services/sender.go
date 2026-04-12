package services

import (
	"context"
	"time"
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

// SendMagicLinkEmail renders the magic link template and delivers via email.
func (s *notificationService) SendMagicLinkEmail(ctx context.Context, email, userName, magicLink, code, expiryTime string) error {
	tmpl, ok := s.emailTemplates["magic_link"]
	if !ok {
		return nil
	}

	if s.emailSender == nil {
		return nil
	}

	data := map[string]interface{}{
		"UserName":   userName,
		"MagicLink":  magicLink,
		"Code":       code,
		"ExpiryTime": expiryTime,
	}

	return s.sendTemplatedEmail(ctx, &tmpl, email, data)
}

// SendInvitationEmail renders the standalone invitation template and delivers via email.
func (s *notificationService) SendInvitationEmail(ctx context.Context, email, inviterName, purpose, inviteLink string, expiresAt time.Time) error {
	tmpl, ok := s.emailTemplates["invitation"]
	if !ok || s.emailSender == nil {
		return nil
	}

	data := map[string]interface{}{
		"InviterName": inviterName,
		"Purpose":     purpose,
		"InviteLink":  inviteLink,
		"ExpiresAt":   expiresAt.Format("January 2, 2006"),
	}

	return s.sendTemplatedEmail(ctx, &tmpl, email, data)
}

// SendOrgInvitationEmail renders the org invitation template and delivers via email.
func (s *notificationService) SendOrgInvitationEmail(ctx context.Context, email, inviterName, orgName, role, inviteLink string, expiresAt time.Time) error {
	tmpl, ok := s.emailTemplates["org_invitation"]
	if !ok || s.emailSender == nil {
		return nil
	}

	data := map[string]interface{}{
		"InviterName": inviterName,
		"OrgName":     orgName,
		"Role":        role,
		"InviteLink":  inviteLink,
		"ExpiresAt":   expiresAt.Format("January 2, 2006"),
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
