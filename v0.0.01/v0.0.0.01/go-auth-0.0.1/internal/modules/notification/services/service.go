package services

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	htmlTemplate "html/template"
	textTemplate "text/template"

	"github.com/bete7512/goauth/internal/modules/notification/models"
	"github.com/bete7512/goauth/pkg/config"
)

// NotificationService handles sending notifications
type NotificationService struct {
	deps        config.ModuleDependencies
	emailSender models.EmailSender
	smsSender   models.SMSSender
	templates   map[string]models.NotificationTemplate
	config      *NotificationConfig
}

// NotificationConfig holds notification service configuration
type NotificationConfig struct {
	AppName           string
	SupportEmail      string
	SupportLink       string
	EnableEmailAlerts bool
	EnableSMSAlerts   bool
	Templates         map[string]models.NotificationTemplate
}

// NewNotificationService creates a new notification service
func NewNotificationService(
	deps config.ModuleDependencies,
	emailSender models.EmailSender,
	smsSender models.SMSSender,
	cfg *NotificationConfig,
) *NotificationService {
	if cfg == nil {
		cfg = &NotificationConfig{
			AppName:           "GoAuth",
			EnableEmailAlerts: true,
			EnableSMSAlerts:   false,
			Templates:         make(map[string]models.NotificationTemplate),
		}
	}

	// Initialize default templates
	templates := map[string]models.NotificationTemplate{
		"welcome":            models.TemplateWelcome,
		"password_reset":     models.TemplatePasswordReset,
		"email_verification": models.TemplateEmailVerification,
		"two_factor_code":    models.TemplateTwoFactorCode,
		"login_alert":        models.TemplateLoginAlert,
		"password_changed":   models.TemplatePasswordChanged,
	}

	// Override with custom templates
	for name, tmpl := range cfg.Templates {
		templates[name] = tmpl
	}

	return &NotificationService{
		deps:        deps,
		emailSender: emailSender,
		smsSender:   smsSender,
		templates:   templates,
		config:      cfg,
	}
}

// SendWelcomeEmail sends a welcome email after signup
func (s *NotificationService) SendWelcomeEmail(ctx context.Context, email, userName string) error {
	tmpl, ok := s.templates["welcome"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"AppName":  s.config.AppName,
		"UserName": userName,
	}

	if tmpl.SendEmail && s.config.EnableEmailAlerts && s.emailSender != nil {
		return s.sendTemplatedEmail(ctx, &tmpl, email, data)
	}

	return nil
}

// SendPasswordResetEmail sends password reset email
func (s *NotificationService) SendPasswordResetEmail(ctx context.Context, email, userName, resetLink, code string, expiryTime string) error {
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

	var err error
	if tmpl.SendEmail && s.config.EnableEmailAlerts && s.emailSender != nil {
		err = s.sendTemplatedEmail(ctx, &tmpl, email, data)
	}

	return err
}

// SendPasswordResetSMS sends password reset SMS
func (s *NotificationService) SendPasswordResetSMS(ctx context.Context, phoneNumber, code, expiryTime string) error {
	tmpl, ok := s.templates["password_reset"]
	if !ok || !tmpl.Enabled || !tmpl.SendSMS {
		return nil
	}

	if !s.config.EnableSMSAlerts || s.smsSender == nil {
		return nil
	}

	data := map[string]interface{}{
		"Code":       code,
		"ExpiryTime": expiryTime,
	}

	return s.sendTemplatedSMS(ctx, &tmpl, phoneNumber, data)
}

// SendEmailVerification sends email verification
func (s *NotificationService) SendEmailVerification(ctx context.Context, email, userName, verificationLink, code string) error {
	tmpl, ok := s.templates["email_verification"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"AppName":          s.config.AppName,
		"UserName":         userName,
		"VerificationLink": verificationLink,
		"Code":             code,
	}

	if tmpl.SendEmail && s.config.EnableEmailAlerts && s.emailSender != nil {
		return s.sendTemplatedEmail(ctx, &tmpl, email, data)
	}

	return nil
}

// SendTwoFactorCode sends 2FA code via email or SMS
func (s *NotificationService) SendTwoFactorCode(ctx context.Context, email, phoneNumber, code string, expiryTime string) error {
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
	if tmpl.SendEmail && s.config.EnableEmailAlerts && s.emailSender != nil && email != "" {
		emailErr = s.sendTemplatedEmail(ctx, &tmpl, email, data)
	}

	// Send via SMS
	if tmpl.SendSMS && s.config.EnableSMSAlerts && s.smsSender != nil && phoneNumber != "" {
		smsErr = s.sendTemplatedSMS(ctx, &tmpl, phoneNumber, data)
	}

	// Return error only if both failed
	if emailErr != nil && smsErr != nil {
		return fmt.Errorf("failed to send 2FA code via email (%v) and SMS (%v)", emailErr, smsErr)
	}

	return nil
}

// SendLoginAlert sends login alert notification
func (s *NotificationService) SendLoginAlert(ctx context.Context, email, userName, ipAddress, timestamp string) error {
	tmpl, ok := s.templates["login_alert"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"UserName":  userName,
		"IPAddress": ipAddress,
		"Timestamp": timestamp,
	}

	if tmpl.SendEmail && s.config.EnableEmailAlerts && s.emailSender != nil {
		return s.sendTemplatedEmail(ctx, &tmpl, email, data)
	}

	return nil
}

// SendPasswordChangedAlert sends password changed notification
func (s *NotificationService) SendPasswordChangedAlert(ctx context.Context, email, userName, timestamp string) error {
	tmpl, ok := s.templates["password_changed"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"UserName":    userName,
		"Timestamp":   timestamp,
		"SupportLink": s.config.SupportLink,
	}

	if tmpl.SendEmail && s.config.EnableEmailAlerts && s.emailSender != nil {
		return s.sendTemplatedEmail(ctx, &tmpl, email, data)
	}

	return nil
}

// sendTemplatedEmail sends an email using a template
func (s *NotificationService) sendTemplatedEmail(ctx context.Context, tmpl *models.NotificationTemplate, to string, data map[string]interface{}) error {
	// Parse and execute subject template
	subjectTmpl, err := template.New("subject").Parse(tmpl.Subject)
	if err != nil {
		return fmt.Errorf("failed to parse subject template: %w", err)
	}

	var subjectBuf bytes.Buffer
	if err := subjectTmpl.Execute(&subjectBuf, data); err != nil {
		return fmt.Errorf("failed to execute subject template: %w", err)
	}

	// Parse and execute text body template
	textTmpl, err := textTemplate.New("text").Parse(tmpl.TextBody)
	if err != nil {
		return fmt.Errorf("failed to parse text template: %w", err)
	}

	var textBuf bytes.Buffer
	if err := textTmpl.Execute(&textBuf, data); err != nil {
		return fmt.Errorf("failed to execute text template: %w", err)
	}

	// Parse and execute HTML body template
	var htmlBuf bytes.Buffer
	if tmpl.HTMLBody != "" {
		htmlTmpl, err := htmlTemplate.New("html").Parse(tmpl.HTMLBody)
		if err != nil {
			return fmt.Errorf("failed to parse HTML template: %w", err)
		}

		if err := htmlTmpl.Execute(&htmlBuf, data); err != nil {
			return fmt.Errorf("failed to execute HTML template: %w", err)
		}
	}

	// Send email
	message := &models.EmailMessage{
		To:       []string{to},
		Subject:  subjectBuf.String(),
		TextBody: textBuf.String(),
		HTMLBody: htmlBuf.String(),
	}

	return s.emailSender.SendEmail(ctx, message)
}

// sendTemplatedSMS sends an SMS using a template
func (s *NotificationService) sendTemplatedSMS(ctx context.Context, tmpl *models.NotificationTemplate, to string, data map[string]interface{}) error {
	// Parse and execute SMS body template
	smsTmpl, err := textTemplate.New("sms").Parse(tmpl.SMSBody)
	if err != nil {
		return fmt.Errorf("failed to parse SMS template: %w", err)
	}

	var smsBuf bytes.Buffer
	if err := smsTmpl.Execute(&smsBuf, data); err != nil {
		return fmt.Errorf("failed to execute SMS template: %w", err)
	}

	// Send SMS
	message := &models.SMSMessage{
		To:   to,
		Body: smsBuf.String(),
	}

	return s.smsSender.SendSMS(ctx, message)
}

// SendCustomEmail sends a custom email
func (s *NotificationService) SendCustomEmail(ctx context.Context, message *models.EmailMessage) error {
	if s.emailSender == nil {
		return fmt.Errorf("email sender not configured")
	}
	return s.emailSender.SendEmail(ctx, message)
}

// SendCustomSMS sends a custom SMS
func (s *NotificationService) SendCustomSMS(ctx context.Context, message *models.SMSMessage) error {
	if s.smsSender == nil {
		return fmt.Errorf("SMS sender not configured")
	}
	return s.smsSender.SendSMS(ctx, message)
}
