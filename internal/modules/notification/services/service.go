package services

//go:generate mockgen -destination=../../../mocks/mock_notification_service.go -package=mocks github.com/bete7512/goauth/internal/modules/notification/services NotificationService

import (
	"context"

	"github.com/bete7512/goauth/internal/modules/notification/models"
	"github.com/bete7512/goauth/internal/modules/notification/templates"
	pkgmodels "github.com/bete7512/goauth/pkg/models"
)

// NotificationService defines the notification delivery operations.
// This is a pure delivery layer -- no database access, no user mutations.
type NotificationService interface {
	SendEmailVerification(ctx context.Context, email, userName, verificationLink string) error
	SendPhoneVerification(ctx context.Context, phoneNumber, userName, code, expiryTime string) error
	SendPasswordResetEmail(ctx context.Context, email, userName, resetLink, code, expiryTime string) error
	SendPasswordResetSMS(ctx context.Context, phoneNumber, code, expiryTime string) error
	SendWelcomeEmail(ctx context.Context, user pkgmodels.User) error
	SendLoginAlert(ctx context.Context, user pkgmodels.User, metadata map[string]interface{}) error
	SendPasswordChangedAlert(ctx context.Context, user pkgmodels.User) error
	SendMagicLinkEmail(ctx context.Context, email, userName, magicLink, code, expiryTime string) error
	SendCustomEmail(ctx context.Context, message *models.EmailMessage) error
	SendCustomSMS(ctx context.Context, message *models.SMSMessage) error
}

// NotificationConfig holds notification service configuration.
type NotificationConfig struct {
	// Branding injected into every template (logo, colors, company name, etc.).
	// If nil, defaults to GoAuth branding.
	Branding *templates.Branding

	// EmailTemplates overrides individual email templates by name.
	EmailTemplates map[string]templates.EmailTemplate

	// SMSTemplates overrides individual SMS templates by name.
	SMSTemplates map[string]templates.SMSTemplate
}

type notificationService struct {
	emailSender    models.EmailSender
	smsSender      models.SMSSender
	emailTemplates map[string]templates.EmailTemplate
	smsTemplates   map[string]templates.SMSTemplate
	baseHTML       string
	branding       *templates.Branding
}

// NewNotificationService creates a new notification service (delivery only).
func NewNotificationService(
	emailSender models.EmailSender,
	smsSender models.SMSSender,
	cfg *NotificationConfig,
) NotificationService {
	if cfg == nil {
		cfg = &NotificationConfig{}
	}

	// Resolve branding
	branding := cfg.Branding
	if branding == nil {
		branding = templates.DefaultBranding()
	}

	// Load base layout and default templates from embedded FS
	baseHTML := templates.LoadBaseHTML()
	emailTmplMap := templates.DefaultEmailTemplates()
	smsTmplMap := templates.DefaultSMSTemplates()

	// Apply per-template overrides (most specific wins)
	for name, tmpl := range cfg.EmailTemplates {
		emailTmplMap[name] = tmpl
	}
	for name, tmpl := range cfg.SMSTemplates {
		smsTmplMap[name] = tmpl
	}

	return &notificationService{
		emailSender:    emailSender,
		smsSender:      smsSender,
		emailTemplates: emailTmplMap,
		smsTemplates:   smsTmplMap,
		baseHTML:       baseHTML,
		branding:       branding,
	}
}
