package models

import "context"

// EmailMessage represents an email to be sent
type EmailMessage struct {
	To          []string          // Recipients
	From        string            // Sender email
	FromName    string            // Sender name
	Subject     string            // Email subject
	TextBody    string            // Plain text body
	HTMLBody    string            // HTML body
	CC          []string          // CC recipients
	BCC         []string          // BCC recipients
	ReplyTo     string            // Reply-to address
	Attachments []Attachment      // File attachments
	Headers     map[string]string // Custom headers
}

// SMSMessage represents an SMS to be sent
type SMSMessage struct {
	To       string   // Recipient phone number (E.164 format)
	From     string   // Sender phone number
	Body     string   // Message body
	MediaURL []string // MMS media URLs (optional)
}

// Attachment represents an email attachment
type Attachment struct {
	Filename    string
	Content     []byte
	ContentType string
}

// EmailSender interface for sending emails
type EmailSender interface {
	SendEmail(ctx context.Context, message *EmailMessage) error
	VerifyConfig(ctx context.Context) error
}

// SMSSender interface for sending SMS
type SMSSender interface {
	SendSMS(ctx context.Context, message *SMSMessage) error
	VerifyConfig(ctx context.Context) error
}
