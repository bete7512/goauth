package hooks

import (
	"context"
	"fmt"

	"github.com/bete7512/goauth/internal/modules/notification/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// NotificationHooks manages event hooks for notifications.
type NotificationHooks struct {
	service services.NotificationService
	deps    config.ModuleDependencies
	config  *HookConfig
}

// HookConfig controls which notifications are enabled.
type HookConfig struct {
	EnableWelcomeEmail        bool
	EnablePasswordResetEmail  bool
	EnablePasswordResetSMS    bool
	EnableLoginAlerts         bool
	EnablePasswordChangeAlert bool
	Enable2FANotifications    bool
	EnableMagicLinkEmail      bool
}

// NewNotificationHooks creates a new hooks manager.
func NewNotificationHooks(service services.NotificationService, deps config.ModuleDependencies, cfg *HookConfig) *NotificationHooks {
	return &NotificationHooks{
		service: service,
		deps:    deps,
		config:  cfg,
	}
}

// GetHooks returns all event hooks to register.
func (h *NotificationHooks) GetHooks() []EventHook {
	hooks := []EventHook{}

	// Welcome email after signup
	if h.config.EnableWelcomeEmail {
		hooks = append(hooks, EventHook{
			Event:   types.EventAfterSignup,
			Handler: h.sendWelcomeEmail,
		})
	}

	// Email verification delivery
	hooks = append(hooks, EventHook{
		Event:   types.EventSendEmailVerification,
		Handler: h.handleSendEmailVerification,
	})

	// Phone verification delivery
	if h.config.Enable2FANotifications {
		hooks = append(hooks, EventHook{
			Event:   types.EventSendPhoneVerification,
			Handler: h.handleSendPhoneVerification,
		})
	}

	// Password reset email/SMS delivery
	if h.config.EnablePasswordResetEmail || h.config.EnablePasswordResetSMS {
		hooks = append(hooks, EventHook{
			Event:   types.EventSendPasswordResetEmail,
			Handler: h.handleSendPasswordReset,
		})
	}

	// Password changed alert (fires for both change-password and reset-password)
	if h.config.EnablePasswordChangeAlert {
		hooks = append(hooks, EventHook{
			Event:   types.EventAfterChangePassword,
			Handler: h.handlePasswordChanged,
		})
		hooks = append(hooks, EventHook{
			Event:   types.EventAfterResetPassword,
			Handler: h.handlePasswordChanged,
		})
	}

	// Magic link email delivery
	if h.config.EnableMagicLinkEmail {
		hooks = append(hooks, EventHook{
			Event:   types.EventSendMagicLink,
			Handler: h.handleSendMagicLink,
		})
	}

	// Login alert
	if h.config.EnableLoginAlerts {
		hooks = append(hooks, EventHook{
			Event:   types.EventAfterLogin,
			Handler: h.handleLoginAlert,
		})
	}

	return hooks
}

// EventHook represents an event and its handler.
type EventHook struct {
	Event   types.EventType
	Handler types.EventHandler
}

// --- Handler implementations ---

func (h *NotificationHooks) sendWelcomeEmail(ctx context.Context, event *types.Event) error {
	data, ok := types.EventDataAs[*types.UserEventData](event)
	if !ok {
		return fmt.Errorf("notification: unexpected event data type for %s (id=%s)", event.Type, event.ID)
	}

	if err := h.service.SendWelcomeEmail(ctx, *data.User); err != nil {
		h.deps.Logger.Errorf("notification: failed to send welcome email: %v", err)
		return err
	}

	h.deps.Logger.Infof("notification: Welcome Email sent to %s", data.User.Email)

	return nil
}

func (h *NotificationHooks) handleSendEmailVerification(ctx context.Context, event *types.Event) error {
	data, ok := types.EventDataAs[*types.EmailVerificationRequestData](event)
	if !ok {
		return fmt.Errorf("notification: unexpected event data type for %s (id=%s)", event.Type, event.ID)
	}

	if err := h.service.SendEmailVerification(ctx, data.User.Email, data.User.Name, data.VerificationLink); err != nil {
		h.deps.Logger.Errorf("notification: failed to send email verification: %v", err)
		return err
	}

	h.deps.Logger.Infof("notification: sent email verification to %s", data.User.Email)
	return nil
}

func (h *NotificationHooks) handleSendPhoneVerification(ctx context.Context, event *types.Event) error {
	data, ok := types.EventDataAs[*types.PhoneVerificationRequestData](event)
	if !ok {
		return fmt.Errorf("notification: unexpected event data type for %s (id=%s)", event.Type, event.ID)
	}

	if err := h.service.SendPhoneVerification(ctx, data.User.PhoneNumber, data.User.Name, data.Code, data.ExpiryTime); err != nil {
		h.deps.Logger.Errorf("notification: failed to send phone verification: %v", err)
		return err
	}

	h.deps.Logger.Infof("notification: sent phone verification to %s", data.User.PhoneNumber)
	return nil
}

func (h *NotificationHooks) handleSendPasswordReset(ctx context.Context, event *types.Event) error {
	data, ok := types.EventDataAs[*types.PasswordResetRequestData](event)
	if !ok {
		return fmt.Errorf("notification: unexpected event data type for %s (id=%s)", event.Type, event.ID)
	}

	// Send email if configured
	if h.config.EnablePasswordResetEmail && data.Email != "" {
		if err := h.service.SendPasswordResetEmail(ctx, data.Email, data.Name, data.ResetLink, data.Code, "1 hour"); err != nil {
			h.deps.Logger.Errorf("notification: failed to send password reset email: %v", err)
			return err
		}
	}

	// Send SMS if configured
	if h.config.EnablePasswordResetSMS && data.PhoneNumber != "" {
		if err := h.service.SendPasswordResetSMS(ctx, data.PhoneNumber, data.Code, "1 hour"); err != nil {
			h.deps.Logger.Errorf("notification: failed to send password reset SMS: %v", err)
			return err
		}
	}

	return nil
}

func (h *NotificationHooks) handlePasswordChanged(ctx context.Context, event *types.Event) error {
	data, ok := types.EventDataAs[*types.PasswordChangedData](event)
	if !ok {
		return fmt.Errorf("notification: unexpected event data type for %s (id=%s)", event.Type, event.ID)
	}

	user := models.User{
		ID:    data.UserID,
		Email: data.Email,
		Name:  data.Name,
	}

	if err := h.service.SendPasswordChangedAlert(ctx, user); err != nil {
		h.deps.Logger.Errorf("notification: failed to send password changed alert: %v", err)
		return err
	}

	return nil
}

func (h *NotificationHooks) handleSendMagicLink(ctx context.Context, event *types.Event) error {
	data, ok := types.EventDataAs[*types.MagicLinkRequestData](event)
	if !ok {
		return fmt.Errorf("notification: unexpected event data type for %s (id=%s)", event.Type, event.ID)
	}

	if err := h.service.SendMagicLinkEmail(ctx, data.User.Email, data.User.Name, data.MagicLink, data.Code, data.ExpiryTime); err != nil {
		h.deps.Logger.Errorf("notification: failed to send magic link email: %v", err)
		return err
	}

	h.deps.Logger.Infof("notification: sent magic link email to %s", data.User.Email)
	return nil
}

func (h *NotificationHooks) handleLoginAlert(ctx context.Context, event *types.Event) error {
	data, ok := types.EventDataAs[*types.LoginEventData](event)
	if !ok {
		return fmt.Errorf("notification: unexpected event data type for %s (id=%s)", event.Type, event.ID)
	}

	metadataMap := map[string]interface{}{}
	if data.Metadata != nil {
		metadataMap["ip_address"] = data.Metadata.IPAddress
		metadataMap["user_agent"] = data.Metadata.UserAgent
		metadataMap["timestamp"] = data.Metadata.Timestamp
		metadataMap["device_fingerprint"] = data.Metadata.DeviceFingerprint
	}

	if err := h.service.SendLoginAlert(ctx, *data.User, metadataMap); err != nil {
		h.deps.Logger.Errorf("notification: failed to send login alert: %v", err)
		return err
	}

	return nil
}
