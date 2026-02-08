package notification

import (
	"context"
	"fmt"

	_ "embed"

	"github.com/bete7512/goauth/internal/modules/notification/hooks"
	"github.com/bete7512/goauth/internal/modules/notification/models"
	"github.com/bete7512/goauth/internal/modules/notification/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type NotificationModule struct {
	deps    config.ModuleDependencies
	service services.NotificationService
	config  *Config
}

// Config holds notification module configuration.
type Config struct {
	// Email sender implementation (optional)
	EmailSender models.EmailSender

	// SMS sender implementation (optional)
	SMSSender models.SMSSender

	// Service configuration (templates, app name, etc.)
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

// New creates a new notification module.
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

	// Validate sender configuration
	if m.config.EmailSender == nil && m.config.SMSSender == nil {
		m.deps.Logger.Warnf("notification module: no email or SMS sender configured, notifications will not be sent")
	}

	// Verify sender connections
	if err := m.verifySenderConnections(ctx); err != nil {
		return err
	}

	// Initialize service (delivery only -- no repos, no DB)
	m.service = services.NewNotificationService(
		m.config.EmailSender,
		m.config.SMSSender,
		m.config.ServiceConfig,
	)

	return nil
}

func (m *NotificationModule) Routes() []config.RouteInfo {
	// Notification module has no HTTP routes -- it's a pure delivery layer.
	// Verification routes are now in the core module.
	return nil
}

func (m *NotificationModule) Middlewares() []config.MiddlewareConfig {
	return []config.MiddlewareConfig{}
}

func (m *NotificationModule) Models() []any {
	// No models -- tokens are owned by core module.
	return []any{}
}

func (m *NotificationModule) RegisterHooks(events types.EventBus) error {
	hookManager := hooks.NewNotificationHooks(m.service, m.deps, &hooks.HookConfig{
		EnableWelcomeEmail:        m.config.EnableWelcomeEmail,
		EnablePasswordResetEmail:  m.config.EnablePasswordResetEmail,
		EnablePasswordResetSMS:    m.config.EnablePasswordResetSMS,
		EnableLoginAlerts:         m.config.EnableLoginAlerts,
		EnablePasswordChangeAlert: m.config.EnablePasswordChangeAlert,
		Enable2FANotifications:    m.config.Enable2FANotifications,
	})

	for _, hook := range hookManager.GetHooks() {
		events.Subscribe(hook.Event, hook.Handler)
	}

	m.deps.Logger.Info("notification module: event hooks registered successfully")
	return nil
}

func (m *NotificationModule) SwaggerSpec() []byte {
	return nil
}

func (m *NotificationModule) Dependencies() []string {
	return []string{string(types.CoreModule)}
}

// GetService returns the notification service for direct access by library users.
func (m *NotificationModule) GetService() services.NotificationService {
	return m.service
}

func (m *NotificationModule) verifySenderConnections(ctx context.Context) error {
	if m.config.EmailSender != nil {
		if err := m.config.EmailSender.VerifyConfig(ctx); err != nil {
			return fmt.Errorf("notification: email sender verification failed: %w", err)
		}
		m.deps.Logger.Info("notification module: email sender connected successfully")
	}

	if m.config.SMSSender != nil {
		if err := m.config.SMSSender.VerifyConfig(ctx); err != nil {
			return fmt.Errorf("notification: SMS sender verification failed: %w", err)
		}
		m.deps.Logger.Info("notification module: SMS sender connected successfully")
	}

	return nil
}
