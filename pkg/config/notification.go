package config

import "github.com/bete7512/goauth/pkg/interfaces"

type SendGridConfig struct {
	FromEmail string
	FromName  string
	APIKey    string
}

type SESConfig struct {
	FromEmail       string
	FromName        string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
}

type EmailConfig struct {
	SenderType EmailSenderType
	// Branding
	Branding BrandingConfig
	// Sendgrid config
	SendGrid SendGridConfig
	// Ses config
	SES SESConfig
	// Custom sender
	CustomSender interfaces.EmailSenderInterface
}

type BrandingConfig struct {
	LogoURL      string
	CompanyName  string
	PrimaryColor string
	SupportEmail string
}

// config/sms.go
type SMSConfig struct {
	// Branding
	Branding BrandingConfig
	// Twilio config
	Twilio TwilioConfig
	// Custom sender
	CustomSender interfaces.SMSSenderInterface
}

type TwilioConfig struct {
	AccountSID string
	AuthToken  string
	FromNumber string
}
