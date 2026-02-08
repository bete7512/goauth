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
	SendCustomEmail(ctx context.Context, message *models.EmailMessage) error
	SendCustomSMS(ctx context.Context, message *models.SMSMessage) error
}

// NotificationConfig holds notification service configuration.
type NotificationConfig struct {
	AppName      string
	SupportEmail string
	SupportLink  string
	Templates    map[string]templates.NotificationTemplate
}

type notificationService struct {
	emailSender models.EmailSender
	smsSender   models.SMSSender
	templates   map[string]templates.NotificationTemplate
	config      *NotificationConfig
}

// NewNotificationService creates a new notification service (delivery only).
func NewNotificationService(
	emailSender models.EmailSender,
	smsSender models.SMSSender,
	cfg *NotificationConfig,
) NotificationService {
	if cfg == nil {
		cfg = &NotificationConfig{
			AppName:   "GoAuth",
			Templates: make(map[string]templates.NotificationTemplate),
		}
	}

	tmplMap := map[string]templates.NotificationTemplate{
		"welcome":            templates.TemplateWelcome,
		"password_reset":     templates.TemplatePasswordReset,
		"email_verification": templates.TemplateEmailVerification,
		"two_factor_code":    templates.TemplateTwoFactorCode,
		"login_alert":        templates.TemplateLoginAlert,
		"password_changed":   templates.TemplatePasswordChanged,
	}

	for name, tmpl := range cfg.Templates {
		tmplMap[name] = tmpl
	}

	return &notificationService{
		emailSender: emailSender,
		smsSender:   smsSender,
		templates:   tmplMap,
		config:      cfg,
	}
}
