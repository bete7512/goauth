// Package senders provides built-in email and SMS sender implementations.
// Import this package instead of internal/modules/notification/services/senders.
package senders

import (
	internal "github.com/bete7512/goauth/internal/modules/notification/services/senders"
)

// Config types — re-exported so callers import only from pkg/.
type (
	ResendConfig   = internal.ResendConfig
	SendGridConfig = internal.SendGridConfig
	SMTPConfig     = internal.SMTPConfig
	TwilioConfig   = internal.TwilioConfig
)

// Constructors — re-exported as function variables preserving original signatures.
var (
	NewResendEmailSender   = internal.NewResendEmailSender
	NewSendGridEmailSender = internal.NewSendGridEmailSender
	NewSMTPEmailSender     = internal.NewSMTPEmailSender
	NewTwilioSMSSender     = internal.NewTwilioSMSSender
)
