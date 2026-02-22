// Package notification exposes the email/SMS notification module.
// Import this package instead of internal/modules/notification.
//
// Type aliases are provided so all developer-facing types (Config, EmailSender,
// Branding, etc.) are importable from this single package path.
package notification

import (
	internal "github.com/bete7512/goauth/internal/modules/notification"
	internal_models "github.com/bete7512/goauth/internal/modules/notification/models"
	internal_templates "github.com/bete7512/goauth/internal/modules/notification/templates"
	"github.com/bete7512/goauth/pkg/config"
)

// Config re-exported for callers.
type Config = internal.Config

// Sender interfaces — implement these to plug in your own email/SMS provider.
type (
	EmailSender = internal_models.EmailSender
	SMSSender   = internal_models.SMSSender
)

// Message types used by the sender interfaces.
type (
	EmailMessage = internal_models.EmailMessage
	SMSMessage   = internal_models.SMSMessage
	Attachment   = internal_models.Attachment
)

// Template types for overriding built-in email/SMS templates.
type (
	Branding      = internal_templates.Branding
	EmailTemplate = internal_templates.EmailTemplate
	SMSTemplate   = internal_templates.SMSTemplate
)

// DefaultEmailTemplates returns the built-in email template map.
// Use this as a starting point when customising individual templates.
var DefaultEmailTemplates = internal_templates.DefaultEmailTemplates

// DefaultSMSTemplates returns the built-in SMS template map.
var DefaultSMSTemplates = internal_templates.DefaultSMSTemplates

// DefaultBranding returns GoAuth default branding values.
var DefaultBranding = internal_templates.DefaultBranding

// New creates the notification module.
// Pass nil for cfg to use safe defaults (welcome + password-reset email enabled).
func New(cfg *Config) config.Module {
	return internal.New(cfg)
}
