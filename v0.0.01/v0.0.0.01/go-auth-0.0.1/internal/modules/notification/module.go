package notification

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/notification/models"
	"github.com/bete7512/goauth/internal/modules/notification/services"
	"github.com/bete7512/goauth/pkg/config"
)

type NotificationModule struct {
	deps    config.ModuleDependencies
	service *services.NotificationService
	config  *Config
}

// Config holds notification module configuration
type Config struct {
	// Email sender implementation (optional - user can provide their own)
	EmailSender models.EmailSender

	// SMS sender implementation (optional - user can provide their own)
	SMSSender models.SMSSender

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
	return string(config.NotificationModule)
}

func (m *NotificationModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

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
	)

	return nil
}

func (m *NotificationModule) Routes() []config.RouteInfo {
	// Notification module doesn't expose any routes
	return nil
}

func (m *NotificationModule) Middlewares() []config.MiddlewareConfig {
	// Notification module doesn't add any middlewares
	return nil
}

func (m *NotificationModule) Models() []interface{} {
	// Notification module doesn't have any database models
	return nil
}

func (m *NotificationModule) RegisterHooks(events config.EventBus) error {
	m.deps.Logger.Info("notification module: registering event hooks")

	// AFTER SIGNUP - Send welcome email
	if m.config.EnableWelcomeEmail {
		events.Subscribe("after:signup", func(ctx context.Context, event interface{}) error {
			m.deps.Logger.Info("notification: after:signup event received")

			data, ok := event.(map[string]interface{})
			if !ok {
				m.deps.Logger.Warnf("notification: invalid event data for after:signup")
				return nil
			}

			email, _ := data["email"].(string)
			userName, _ := data["name"].(string)
			if userName == "" {
				userName = email
			}

			if err := m.service.SendWelcomeEmail(ctx, email, userName); err != nil {
				m.deps.Logger.Errorf("notification: failed to send welcome email: %v", err)
				// Don't return error - we don't want to block signup
			}

			return nil
		})
	}

	// PASSWORD RESET REQUEST - Send reset email/SMS
	if m.config.EnablePasswordResetEmail || m.config.EnablePasswordResetSMS {
		events.Subscribe("password:reset:request", func(ctx context.Context, event interface{}) error {
			m.deps.Logger.Info("notification: password:reset:request event received")

			data, ok := event.(map[string]interface{})
			if !ok {
				return nil
			}

			email, _ := data["email"].(string)
			userName, _ := data["name"].(string)
			resetLink, _ := data["reset_link"].(string)
			code, _ := data["code"].(string)
			phoneNumber, _ := data["phone_number"].(string)

			if userName == "" {
				userName = email
			}

			// Send email
			if m.config.EnablePasswordResetEmail && email != "" {
				if err := m.service.SendPasswordResetEmail(ctx, email, userName, resetLink, code, "15 minutes"); err != nil {
					m.deps.Logger.Errorf("notification: failed to send password reset email: %v", err)
				}
			}

			// Send SMS
			if m.config.EnablePasswordResetSMS && phoneNumber != "" {
				if err := m.service.SendPasswordResetSMS(ctx, phoneNumber, code, "15 minutes"); err != nil {
					m.deps.Logger.Errorf("notification: failed to send password reset SMS: %v", err)
				}
			}

			return nil
		})
	}

	// PASSWORD CHANGED - Send alert
	if m.config.EnablePasswordChangeAlert {
		events.Subscribe("password:changed", func(ctx context.Context, event interface{}) error {
			m.deps.Logger.Info("notification: password:changed event received")

			data, ok := event.(map[string]interface{})
			if !ok {
				return nil
			}

			email, _ := data["email"].(string)
			userName, _ := data["name"].(string)
			timestamp := time.Now().Format("2006-01-02 15:04:05")

			if userName == "" {
				userName = email
			}

			if err := m.service.SendPasswordChangedAlert(ctx, email, userName, timestamp); err != nil {
				m.deps.Logger.Errorf("notification: failed to send password changed alert: %v", err)
			}

			return nil
		})
	}

	// AFTER LOGIN - Send login alert (optional)
	if m.config.EnableLoginAlerts {
		events.Subscribe("after:login", func(ctx context.Context, event interface{}) error {
			m.deps.Logger.Info("notification: after:login event received")

			data, ok := event.(map[string]interface{})
			if !ok {
				return nil
			}

			userMap, _ := data["user"].(map[string]interface{})
			email, _ := userMap["email"].(string)
			userName, _ := userMap["name"].(string)
			ipAddress, _ := data["ip_address"].(string)
			timestamp, _ := data["timestamp"].(string)

			if userName == "" {
				userName = email
			}

			if err := m.service.SendLoginAlert(ctx, email, userName, ipAddress, timestamp); err != nil {
				m.deps.Logger.Errorf("notification: failed to send login alert: %v", err)
			}

			return nil
		})
	}

	// EMAIL VERIFICATION SENT
	events.Subscribe("email:verification:sent", func(ctx context.Context, event interface{}) error {
		m.deps.Logger.Info("notification: email:verification:sent event received")

		data, ok := event.(map[string]interface{})
		if !ok {
			return nil
		}

		email, _ := data["email"].(string)
		userName, _ := data["name"].(string)
		verificationLink, _ := data["verification_link"].(string)
		code, _ := data["code"].(string)

		if userName == "" {
			userName = email
		}

		if err := m.service.SendEmailVerification(ctx, email, userName, verificationLink, code); err != nil {
			m.deps.Logger.Errorf("notification: failed to send email verification: %v", err)
		}

		return nil
	})

	// 2FA VERIFICATION - Send code
	if m.config.Enable2FANotifications {
		events.Subscribe("2fa:code:sent", func(ctx context.Context, event interface{}) error {
			m.deps.Logger.Info("notification: 2fa:code:sent event received")

			data, ok := event.(map[string]interface{})
			if !ok {
				return nil
			}

			email, _ := data["email"].(string)
			phoneNumber, _ := data["phone_number"].(string)
			code, _ := data["code"].(string)

			if err := m.service.SendTwoFactorCode(ctx, email, phoneNumber, code, "5 minutes"); err != nil {
				m.deps.Logger.Errorf("notification: failed to send 2FA code: %v", err)
			}

			return nil
		})
	}

	m.deps.Logger.Info("notification module: event hooks registered successfully")
	return nil
}

func (m *NotificationModule) Dependencies() []string {
	// Notification module depends on core for user events
	return []string{string(config.CoreModule)}
}

// GetService returns the notification service for direct access
func (m *NotificationModule) GetService() *services.NotificationService {
	return m.service
}

func (m *NotificationModule) SwaggerSpec() []byte {
	return nil
}
