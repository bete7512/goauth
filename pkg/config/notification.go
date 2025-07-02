package config

import "github.com/bete7512/goauth/pkg/interfaces"

type SendGridConfig struct {
	APIKey string
}

type SESConfig struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
}

type EmailConfig struct {
	// Sender configuration
	Sender EmailSenderConfig

	// Email content/branding
	Branding EmailBrandingConfig

	// Provider-specific configs
	SendGrid SendGridConfig
	SES      SESConfig
}

type EmailSenderConfig struct {
	Type         SenderType
	FromEmail    string
	FromName     string
	SupportEmail string
	CustomSender interfaces.EmailSenderInterface
}

type EmailBrandingConfig struct {
	LogoURL      string
	CompanyName  string
	PrimaryColor string
}

// config/sms.go
type SMSConfig struct {
	// Twilio config
	Twilio TwilioConfig

	// Branding
	CompanyName  string
	CustomSender interfaces.SMSSenderInterface
}

type TwilioConfig struct {
	AccountSID string
	AuthToken  string
	FromNumber string
}
