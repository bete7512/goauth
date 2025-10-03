package senders

import (
	"context"
	"fmt"

	"github.com/bete7512/goauth/internal/modules/notification/models"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// SendGridEmailSender implements EmailSender using SendGrid
type SendGridEmailSender struct {
	apiKey          string
	client          *sendgrid.Client
	defaultFrom     string
	defaultFromName string
}

// SendGridConfig holds SendGrid configuration
type SendGridConfig struct {
	APIKey          string
	DefaultFrom     string
	DefaultFromName string
}

// NewSendGridEmailSender creates a new SendGrid email sender
func NewSendGridEmailSender(config *SendGridConfig) *SendGridEmailSender {
	return &SendGridEmailSender{
		apiKey:          config.APIKey,
		client:          sendgrid.NewSendClient(config.APIKey),
		defaultFrom:     config.DefaultFrom,
		defaultFromName: config.DefaultFromName,
	}
}

// SendEmail sends an email using SendGrid
func (s *SendGridEmailSender) SendEmail(ctx context.Context, message *models.EmailMessage) error {
	from := mail.NewEmail(message.FromName, message.From)
	if message.From == "" {
		from = mail.NewEmail(s.defaultFromName, s.defaultFrom)
	}

	// Create personalization for multiple recipients
	personalization := mail.NewPersonalization()
	for _, to := range message.To {
		personalization.AddTos(mail.NewEmail("", to))
	}
	for _, cc := range message.CC {
		personalization.AddCCs(mail.NewEmail("", cc))
	}
	for _, bcc := range message.BCC {
		personalization.AddBCCs(mail.NewEmail("", bcc))
	}

	// Create email
	email := mail.NewV3Mail()
	email.SetFrom(from)
	email.Subject = message.Subject
	email.AddPersonalizations(personalization)

	// Add content
	if message.TextBody != "" {
		email.AddContent(mail.NewContent("text/plain", message.TextBody))
	}
	if message.HTMLBody != "" {
		email.AddContent(mail.NewContent("text/html", message.HTMLBody))
	}

	// Add attachments
	for _, att := range message.Attachments {
		attachment := mail.NewAttachment()
		attachment.SetFilename(att.Filename)
		attachment.SetType(att.ContentType)
		attachment.SetContent(string(att.Content))
		email.AddAttachment(attachment)
	}

	// Add reply-to
	if message.ReplyTo != "" {
		email.SetReplyTo(mail.NewEmail("", message.ReplyTo))
	}

	// Send
	response, err := s.client.SendWithContext(ctx, email)
	if err != nil {
		return fmt.Errorf("sendgrid: failed to send email: %w", err)
	}

	if response.StatusCode >= 400 {
		return fmt.Errorf("sendgrid: server returned status %d: %s", response.StatusCode, response.Body)
	}

	return nil
}

// VerifyConnection verifies the SendGrid API connection
func (s *SendGridEmailSender) VerifyConnection(ctx context.Context) error {
	if s.apiKey == "" {
		return fmt.Errorf("sendgrid: API key is required")
	}
	// SendGrid doesn't have a ping endpoint, so we just verify the API key exists
	return nil
}
