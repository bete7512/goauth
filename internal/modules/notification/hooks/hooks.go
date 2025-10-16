package hooks

import (
	"context"

	coreModels "github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/internal/modules/notification/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// NotificationHooks manages event hooks for notifications
type NotificationHooks struct {
	service *services.NotificationService
	deps    config.ModuleDependencies
	config  *HookConfig
}

// HookConfig controls which notifications are enabled
type HookConfig struct {
	EnableWelcomeEmail        bool
	EnablePasswordResetEmail  bool
	EnablePasswordResetSMS    bool
	EnableLoginAlerts         bool
	EnablePasswordChangeAlert bool
	Enable2FANotifications    bool
}

// NewNotificationHooks creates a new hooks manager
func NewNotificationHooks(service *services.NotificationService, deps config.ModuleDependencies, cfg *HookConfig) *NotificationHooks {
	return &NotificationHooks{
		service: service,
		deps:    deps,
		config:  cfg,
	}
}

// GetHooks returns all event hooks to register
func (h *NotificationHooks) GetHooks() []EventHook {
	hooks := []EventHook{}

	// Welcome email after signup
	if h.config.EnableWelcomeEmail && !h.deps.Config.Core.RequireEmailVerification {
		hooks = append(hooks, EventHook{
			Event:   types.EventAfterSignup,
			Handler: h.handleAfterSignup,
		})
	}

	// Email verification
	hooks = append(hooks, EventHook{
		Event:   types.EventSendEmailVerification,
		Handler: h.handleSendEmailVerification,
	})

	// Phone verification
	if h.config.Enable2FANotifications {
		hooks = append(hooks, EventHook{
			Event:   types.EventSendPhoneVerification,
			Handler: h.handleSendPhoneVerification,
		})
	}

	// Password changed alert
	if h.config.EnablePasswordChangeAlert {
		hooks = append(hooks, EventHook{
			Event:   types.EventAfterChangePassword,
			Handler: h.handlePasswordChanged,
		})
	}

	// Login alert
	if h.config.EnableLoginAlerts {
		hooks = append(hooks, EventHook{
			Event:   types.EventAfterLogin,
			Handler: h.handleLoginAlert,
		})
	}

	// Email verified - send welcome
	if h.config.EnableWelcomeEmail {
		hooks = append(hooks, EventHook{
			Event:   types.EventAfterEmailVerified,
			Handler: h.handleAfterEmailVerified,
		})
	}

	return hooks
}

// EventHook represents an event and its handler
type EventHook struct {
	Event   types.EventType
	Handler types.EventHandler
}

// Handler implementations

func (h *NotificationHooks) handleAfterSignup(ctx context.Context, event *types.Event) error {
	data, ok := event.Data.(map[string]interface{})
	if !ok {
		return nil
	}

	user, ok := data["user"].(coreModels.User)
	if !ok {
		h.deps.Logger.Warnf("notification: invalid user data for after:signup")
		return nil
	}

	if err := h.service.SendWelcomeEmail(ctx, user); err != nil {
		h.deps.Logger.Errorf("notification: failed to send welcome email: %v", err)
		return err
	}

	return nil
}

func (h *NotificationHooks) handleSendEmailVerification(ctx context.Context, event *types.Event) error {
	data, ok := event.Data.(map[string]interface{})
	if !ok {
		h.deps.Logger.Warnf("notification: invalid event data for send:email-verification")
		return nil
	}

	user, ok := data["user"].(coreModels.User)
	if !ok {
		h.deps.Logger.Warnf("notification: invalid user data for send:email-verification")
		return nil
	}

	if err := h.service.SendEmailVerificationFromHook(ctx, user); err != nil {
		h.deps.Logger.Errorf("notification: failed to send email verification: %v", err)
		return err
	}

	h.deps.Logger.Infof("notification: sent email verification to %s", user.Email)
	return nil
}

func (h *NotificationHooks) handleSendPhoneVerification(ctx context.Context, event *types.Event) error {
	data, ok := event.Data.(map[string]interface{})
	if !ok {
		h.deps.Logger.Warnf("notification: invalid event data for send:phone-verification")
		return nil
	}

	user, ok := data["user"].(coreModels.User)
	if !ok {
		h.deps.Logger.Warnf("notification: invalid user data for send:phone-verification")
		return nil
	}

	if err := h.service.SendPhoneVerificationFromHook(ctx, user); err != nil {
		h.deps.Logger.Errorf("notification: failed to send phone verification: %v", err)
		return err
	}

	h.deps.Logger.Infof("notification: sent phone verification to %s", user.PhoneNumber)
	return nil
}

func (h *NotificationHooks) handlePasswordChanged(ctx context.Context, event *types.Event) error {
	data, ok := event.Data.(map[string]interface{})
	if !ok {
		return nil
	}

	user, ok := data["user"].(coreModels.User)
	if !ok {
		h.deps.Logger.Warnf("notification: invalid user data for password:changed")
		return nil
	}

	if err := h.service.SendPasswordChangedAlert(ctx, user); err != nil {
		h.deps.Logger.Errorf("notification: failed to send password changed alert: %v", err)
		return err
	}

	return nil
}

func (h *NotificationHooks) handleLoginAlert(ctx context.Context, event *types.Event) error {
	data, ok := event.Data.(map[string]interface{})
	if !ok {
		h.deps.Logger.Warnf("notification: invalid event data for after:login")
		return nil
	}

	metadata, ok := data["metadata"].(map[string]interface{})
	if !ok {
		h.deps.Logger.Warnf("notification: invalid metadata data for after:login")
		return nil
	}

	user, ok := data["user"].(coreModels.User)
	if !ok {
		h.deps.Logger.Warnf("notification: invalid user data for after:login")
		return nil
	}

	if err := h.service.SendLoginAlert(ctx, user, metadata); err != nil {
		h.deps.Logger.Errorf("notification: failed to send login alert: %v", err)
		return err
	}

	return nil
}

func (h *NotificationHooks) handleAfterEmailVerified(ctx context.Context, event *types.Event) error {
	data, ok := event.Data.(map[string]interface{})
	if !ok {
		return nil
	}
	user, ok := data["user"].(coreModels.User)
	if !ok {
		h.deps.Logger.Warnf("notification: invalid user data for after:change-email-verification")
		return nil
	}

	if err := h.service.SendWelcomeEmail(ctx, user); err != nil {
		h.deps.Logger.Errorf("notification: failed to send welcome after verification: %v", err)
	}

	return nil
}
