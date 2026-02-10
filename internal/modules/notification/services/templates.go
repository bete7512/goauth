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

// injectBranding adds Brand data to the template data map.
// Called once per send — every template gets branding automatically.
func (s *notificationService) injectBranding(data map[string]interface{}) map[string]interface{} {
	data["Brand"] = s.branding.BrandingData()
	return data
}

// sendTemplatedEmail renders base layout + content template and sends an email.
func (s *notificationService) sendTemplatedEmail(ctx context.Context, tmpl *templates.EmailTemplate, to string, data map[string]interface{}) error {
	data = s.injectBranding(data)

	// Subject
	subjectTmpl, err := template.New("subject").Parse(tmpl.Subject)
	if err != nil {
		return fmt.Errorf("failed to parse subject template: %w", err)
	}
	var subjectBuf bytes.Buffer
	if err := subjectTmpl.Execute(&subjectBuf, data); err != nil {
		return fmt.Errorf("failed to execute subject template: %w", err)
	}

	// Plain text (no base layout — just content)
	textTmpl, err := textTemplate.New("text").Parse(tmpl.TextBody)
	if err != nil {
		return fmt.Errorf("failed to parse text template: %w", err)
	}
	var textBuf bytes.Buffer
	if err := textTmpl.Execute(&textBuf, data); err != nil {
		return fmt.Errorf("failed to execute text template: %w", err)
	}

	// HTML (base layout wraps content template)
	var htmlBuf bytes.Buffer
	if tmpl.HTMLBody != "" && s.baseHTML != "" {
		// Parse base layout first, then add content block
		htmlTmpl, err := template.New("base").Parse(s.baseHTML)
		if err != nil {
			return fmt.Errorf("failed to parse base HTML template: %w", err)
		}
		if _, err := htmlTmpl.Parse(tmpl.HTMLBody); err != nil {
			return fmt.Errorf("failed to parse content HTML template: %w", err)
		}
		if err := htmlTmpl.Execute(&htmlBuf, data); err != nil {
			return fmt.Errorf("failed to execute HTML template: %w", err)
		}
	} else if tmpl.HTMLBody != "" {
		// No base layout — render content directly
		htmlTmpl, err := template.New("html").Parse(tmpl.HTMLBody)
		if err != nil {
			return fmt.Errorf("failed to parse HTML template: %w", err)
		}
		if err := htmlTmpl.Execute(&htmlBuf, data); err != nil {
			return fmt.Errorf("failed to execute HTML template: %w", err)
		}
	}

	message := &models.EmailMessage{
		To:       []string{to},
		Subject:  subjectBuf.String(),
		TextBody: textBuf.String(),
		HTMLBody: htmlBuf.String(),
	}

	return s.emailSender.SendEmail(ctx, message)
}

// sendTemplatedSMS renders an SMS template and sends it.
func (s *notificationService) sendTemplatedSMS(ctx context.Context, tmpl *templates.SMSTemplate, to string, data map[string]interface{}) error {
	data = s.injectBranding(data)

	smsTmpl, err := textTemplate.New("sms").Parse(tmpl.Body)
	if err != nil {
		return fmt.Errorf("failed to parse SMS template: %w", err)
	}

	var smsBuf bytes.Buffer
	if err := smsTmpl.Execute(&smsBuf, data); err != nil {
		return fmt.Errorf("failed to execute SMS template: %w", err)
	}

	message := &models.SMSMessage{
		To:   to,
		Body: smsBuf.String(),
	}

	return s.smsSender.SendSMS(ctx, message)
}

// SendCustomEmail sends a custom email bypassing templates.
func (s *notificationService) SendCustomEmail(ctx context.Context, message *models.EmailMessage) error {
	if s.emailSender == nil {
		return fmt.Errorf("email sender not configured")
	}
	return s.emailSender.SendEmail(ctx, message)
}

// SendCustomSMS sends a custom SMS bypassing templates.
func (s *notificationService) SendCustomSMS(ctx context.Context, message *models.SMSMessage) error {
	if s.smsSender == nil {
		return fmt.Errorf("SMS sender not configured")
	}
	return s.smsSender.SendSMS(ctx, message)
}
