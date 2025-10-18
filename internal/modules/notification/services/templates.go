package services

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	textTemplate "text/template"

	"github.com/bete7512/goauth/internal/modules/notification/models"
	"github.com/bete7512/goauth/internal/modules/notification/templates"
)

// sendTemplatedEmail sends an email using a template
func (s *NotificationService) sendTemplatedEmail(ctx context.Context, tmpl *templates.NotificationTemplate, to string, data map[string]interface{}) error {
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
		htmlTmpl, err := template.New("html").Parse(tmpl.HTMLBody)
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
func (s *NotificationService) sendTemplatedSMS(ctx context.Context, tmpl *templates.NotificationTemplate, to string, data map[string]interface{}) error {
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
