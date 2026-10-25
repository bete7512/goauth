// Package senders provides built-in email and SMS sender implementations.
// Import this package instead of internal/modules/notification/services/senders.
package senders

import (
	internal "github.com/bete7512/goauth/internal/modules/notification/services/senders"
)

// Config types — re-exported so callers import only from pkg/.
type (
	// ResendConfig configures the Resend email sender.
	ResendConfig = internal.ResendConfig
	// SendGridConfig configures the SendGrid email sender.
	SendGridConfig = internal.SendGridConfig
	// SMTPConfig configures the SMTP email sender.
	SMTPConfig = internal.SMTPConfig
	// TwilioConfig configures the Twilio SMS sender.
	TwilioConfig = internal.TwilioConfig
)

// Constructors — re-exported as function variables preserving original signatures.
var (
	NewResendEmailSender   = internal.NewResendEmailSender
	NewSendGridEmailSender = internal.NewSendGridEmailSender
	NewSMTPEmailSender     = internal.NewSMTPEmailSender
	NewTwilioSMSSender     = internal.NewTwilioSMSSender
)
