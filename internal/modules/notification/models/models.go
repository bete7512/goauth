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

// NotificationTemplate represents a notification template
type NotificationTemplate struct {
	Name      string
	Subject   string // For email
	TextBody  string
	HTMLBody  string // For email
	SMSBody   string // For SMS
	Enabled   bool
	SendEmail bool
	SendSMS   bool
}

// Common notification templates
var (
	TemplateWelcome = NotificationTemplate{
		Name:      "welcome",
		Subject:   "Welcome to {{.AppName}}!",
		TextBody:  "Hi {{.UserName}},\n\nWelcome to {{.AppName}}! Your account has been created successfully.",
		HTMLBody:  "<h1>Welcome {{.UserName}}!</h1><p>Your account has been created successfully.</p>",
		SMSBody:   "Welcome to {{.AppName}}! Your account is ready.",
		Enabled:   true,
		SendEmail: true,
		SendSMS:   false,
	}

	TemplatePasswordReset = NotificationTemplate{
		Name:      "password_reset",
		Subject:   "Password Reset Request",
		TextBody:  "Hi {{.UserName}},\n\nClick here to reset your password: {{.ResetLink}}\n\nThis link expires in {{.ExpiryTime}}.",
		HTMLBody:  "<h2>Password Reset</h2><p>Click <a href='{{.ResetLink}}'>here</a> to reset your password.</p><p>This link expires in {{.ExpiryTime}}.</p>",
		SMSBody:   "Your password reset code is: {{.Code}}. Valid for {{.ExpiryTime}}.",
		Enabled:   true,
		SendEmail: true,
		SendSMS:   true,
	}

	TemplateEmailVerification = NotificationTemplate{
		Name:      "email_verification",
		Subject:   "Verify Your Email",
		TextBody:  "Hi {{.UserName}},\n\nPlease verify your email by clicking: {{.VerificationLink}}",
		HTMLBody:  "<h2>Email Verification</h2><p>Click <a href='{{.VerificationLink}}'>here</a> to verify your email.</p>",
		SMSBody:   "Your verification code is: {{.Code}}",
		Enabled:   true,
		SendEmail: true,
		SendSMS:   false,
	}

	TemplateTwoFactorCode = NotificationTemplate{
		Name:      "two_factor_code",
		Subject:   "Your 2FA Code",
		TextBody:  "Your 2FA code is: {{.Code}}. Valid for {{.ExpiryTime}}.",
		HTMLBody:  "<h2>Two-Factor Authentication</h2><p>Your code is: <strong>{{.Code}}</strong></p><p>Valid for {{.ExpiryTime}}.</p>",
		SMSBody:   "Your 2FA code is: {{.Code}}. Valid for {{.ExpiryTime}}.",
		Enabled:   true,
		SendEmail: true,
		SendSMS:   true,
	}

	TemplateLoginAlert = NotificationTemplate{
		Name:      "login_alert",
		Subject:   "New Login Detected",
		TextBody:  "Hi {{.UserName}},\n\nA new login was detected from {{.IPAddress}} at {{.Timestamp}}.",
		HTMLBody:  "<h2>New Login</h2><p>Location: {{.IPAddress}}</p><p>Time: {{.Timestamp}}</p>",
		SMSBody:   "New login detected from {{.IPAddress}} at {{.Timestamp}}.",
		Enabled:   false,
		SendEmail: true,
		SendSMS:   false,
	}

	TemplatePasswordChanged = NotificationTemplate{
		Name:      "password_changed",
		Subject:   "Your Password Has Been Changed",
		TextBody:  "Hi {{.UserName}},\n\nYour password was changed at {{.Timestamp}}. If this wasn't you, contact support immediately.",
		HTMLBody:  "<h2>Password Changed</h2><p>Your password was changed at {{.Timestamp}}.</p><p>If this wasn't you, <a href='{{.SupportLink}}'>contact support</a> immediately.</p>",
		SMSBody:   "Your password was changed. If this wasn't you, contact support immediately.",
		Enabled:   true,
		SendEmail: true,
		SendSMS:   false,
	}
)
