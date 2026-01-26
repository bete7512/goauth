package services

import (
	pkgmodels "github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/internal/modules/notification/models"
	"github.com/bete7512/goauth/internal/modules/notification/templates"
	"github.com/bete7512/goauth/pkg/config"
)

// NotificationService handles sending notifications
type NotificationService struct {
	deps                  config.ModuleDependencies
	emailSender           models.EmailSender
	smsSender             models.SMSSender
	templates             map[string]templates.NotificationTemplate
	config                *NotificationConfig
	verificationTokenRepo pkgmodels.VerificationTokenRepository
	userRepo              pkgmodels.UserRepository
}

// NotificationConfig holds notification service configuration
type NotificationConfig struct {
	AppName      string
	SupportEmail string
	SupportLink  string
	Templates    map[string]templates.NotificationTemplate
}

// NewNotificationService creates a new notification service
func NewNotificationService(
	deps config.ModuleDependencies,
	emailSender models.EmailSender,
	smsSender models.SMSSender,
	cfg *NotificationConfig,
	verificationTokenRepo pkgmodels.VerificationTokenRepository,
	userRepo pkgmodels.UserRepository,
) *NotificationService {
	if cfg == nil {
		cfg = &NotificationConfig{
			AppName:   "GoAuth",
			Templates: make(map[string]templates.NotificationTemplate),
		}
	}

	// Initialize default templates
	templates := map[string]templates.NotificationTemplate{
		"welcome":            templates.TemplateWelcome,
		"password_reset":     templates.TemplatePasswordReset,
		"email_verification": templates.TemplateEmailVerification,
		"two_factor_code":    templates.TemplateTwoFactorCode,
		"login_alert":        templates.TemplateLoginAlert,
		"password_changed":   templates.TemplatePasswordChanged,
	}

	// Override with custom templates
	for name, tmpl := range cfg.Templates {
		templates[name] = tmpl
	}

	return &NotificationService{
		deps:                  deps,
		emailSender:           emailSender,
		smsSender:             smsSender,
		templates:             templates,
		config:                cfg,
		verificationTokenRepo: verificationTokenRepo,
		userRepo:              userRepo,
	}
}
