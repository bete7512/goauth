package notification

import (
	"context"
	"fmt"

	_ "embed"

	coreModels "github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/internal/modules/notification/handlers"
	"github.com/bete7512/goauth/internal/modules/notification/hooks"
	"github.com/bete7512/goauth/internal/modules/notification/models"
	"github.com/bete7512/goauth/internal/modules/notification/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type NotificationModule struct {
	deps                  config.ModuleDependencies
	service               *services.NotificationService
	handlers              *handlers.NotificationHandler
	config                *Config
	verificationTokenRepo models.VerificationTokenRepository
	userRepo              coreModels.UserRepository
}

// Config holds notification module configuration
type Config struct {

	// Email sender implementation (optional - user can provide their own)
	EmailSender models.EmailSender

	// SMS sender implementation (optional - user can provide their own)
	SMSSender models.SMSSender

	// Verification token repository (optional - user can provide their own)
	VerificationTokenRepository models.VerificationTokenRepository

	// User repository (optional - user can provide their own)
	UserRepository coreModels.UserRepository

	// Service configuration
	ServiceConfig *services.NotificationConfig

	// Enable/disable specific notifications
	EnableWelcomeEmail        bool
	EnablePasswordResetEmail  bool
	EnablePasswordResetSMS    bool
	EnableLoginAlerts         bool
	EnablePasswordChangeAlert bool
	Enable2FANotifications    bool
}

//go:embed docs/swagger.yml
var swaggerSpec []byte

var _ config.Module = (*NotificationModule)(nil)

// New creates a new notification module
func New(cfg *Config) *NotificationModule {
	if cfg == nil {
		cfg = &Config{
			EnableWelcomeEmail:        true,
			EnablePasswordResetEmail:  true,
			EnablePasswordResetSMS:    false,
			EnableLoginAlerts:         false,
			EnablePasswordChangeAlert: true,
			Enable2FANotifications:    true,
		}
	}

	return &NotificationModule{
		config: cfg,
	}
}

func (m *NotificationModule) Name() string {
	return string(types.NotificationModule)
}

func (m *NotificationModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	// Get verification token repository
	if m.config.VerificationTokenRepository != nil {
		m.verificationTokenRepo = m.config.VerificationTokenRepository
	} else {
		// Try to get from storage
		repo := deps.Storage.GetRepository(string(types.CoreVerificationTokenRepository))
		if repo != nil {
			if verificationRepo, ok := repo.(models.VerificationTokenRepository); ok {
				m.verificationTokenRepo = verificationRepo
			}
		}
	}
	if m.config.UserRepository != nil {
		m.userRepo = m.config.UserRepository
	} else {
		// Try to get from storage
		repo := deps.Storage.GetRepository(string(types.CoreUserRepository))
		if repo != nil {
			if userRepo, ok := repo.(coreModels.UserRepository); ok {
				m.userRepo = userRepo
			}
		}
	}

	// Validate that at least one sender is configured
	if m.config.EmailSender == nil && m.config.SMSSender == nil {
		deps.Logger.Warnf("notification module: no email or SMS sender configured, notifications will not be sent")
	}

	// Verify connections
	if m.config.EmailSender != nil {
		if err := m.config.EmailSender.VerifyConfig(ctx); err != nil {
			return fmt.Errorf("notification: email sender verification failed: %w", err)
		}
		deps.Logger.Info("notification module: email sender connected successfully")
	}

	if m.config.SMSSender != nil {
		if err := m.config.SMSSender.VerifyConfig(ctx); err != nil {
			return fmt.Errorf("notification: SMS sender verification failed: %w", err)
		}
		deps.Logger.Info("notification module: SMS sender connected successfully")
	}

	// Initialize service
	m.service = services.NewNotificationService(
		deps,
		m.config.EmailSender,
		m.config.SMSSender,
		m.config.ServiceConfig,
		m.verificationTokenRepo,
		m.userRepo,
	)

	// Initialize handlers
	m.handlers = handlers.NewNotificationHandler(m.service, deps)

	return nil
}

func (m *NotificationModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return m.handlers.GetRoutes()
}

func (m *NotificationModule) Middlewares() []config.MiddlewareConfig {
	// Notification module doesn't add any middlewares
	return nil
}

func (m *NotificationModule) Models() []interface{} {
	// Notification module now includes verification token model
	models := []interface{}{
		&models.VerificationToken{},
	}
	return models
}

func (m *NotificationModule) RegisterHooks(events types.EventBus) error {
	// Create hooks manager - clean configuration-driven approach
	hookManager := hooks.NewNotificationHooks(m.service, m.deps, &hooks.HookConfig{
		EnableWelcomeEmail:        m.config.EnableWelcomeEmail,
		EnablePasswordResetEmail:  m.config.EnablePasswordResetEmail,
		EnablePasswordResetSMS:    m.config.EnablePasswordResetSMS,
		EnableLoginAlerts:         m.config.EnableLoginAlerts,
		EnablePasswordChangeAlert: m.config.EnablePasswordChangeAlert,
		Enable2FANotifications:    m.config.Enable2FANotifications,
	})

	// Register all hooks - simple loop instead of 300+ lines!
	for _, hook := range hookManager.GetHooks() {
		events.Subscribe(hook.Event, hook.Handler)
	}

	m.deps.Logger.Info("notification module: event hooks registered successfully")
	return nil
}

func (m *NotificationModule) SwaggerSpec() []byte {
	return swaggerSpec
}

func (m *NotificationModule) Dependencies() []string {
	// Notification module depends on core for user events
	return []string{string(types.CoreModule)}
}

// GetService returns the notification service for direct access
func (m *NotificationModule) GetService() *services.NotificationService {
	return m.service
}
