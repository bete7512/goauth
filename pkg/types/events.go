package types

import (
	"context"
)

type EventType string

type Event struct {
	Type    EventType
	Context context.Context
	Data    interface{}
	Error   error
}

// EventBus interface for event handling
type EventBus interface {
	Subscribe(eventType EventType, handler EventHandler, opts ...interface{})
	Emit(ctx context.Context, eventType EventType, data interface{}) error
	EmitSync(ctx context.Context, eventType EventType, data interface{}) error
}

// Handler is a function that handles an event
type EventHandler func(ctx context.Context, event *Event) error

// AsyncBackend defines the interface for async event processing backends
// Users can provide custom implementations (Redis, RabbitMQ, Kafka, etc.)
type AsyncBackend interface {
	// Publish sends an event to the async backend
	Publish(ctx context.Context, eventType EventType, event *Event) error

	// Close gracefully shuts down the backend
	Close() error

	// Name returns the backend name for logging
	Name() string
}

const (
	EventBeforeSignup                     EventType = "before:signup"
	EventAfterSignup                      EventType = "after:signup"
	EventBeforeLogin                      EventType = "before:login"
	EventAfterLogin                       EventType = "after:login"
	EventBeforeLogout                     EventType = "before:logout"
	EventAfterLogout                      EventType = "after:logout"
	EventBeforeForgotPassword             EventType = "before:forgot-password"
	EventAfterForgotPassword              EventType = "after:forgot-password"
	EventBeforeResetPassword              EventType = "before:reset-password"
	EventAfterResetPassword               EventType = "after:reset-password"
	EventBeforeChangePassword             EventType = "before:change-password"
	EventAfterChangePassword              EventType = "after:change-password"
	EventBeforeChangeEmail                EventType = "before:change-email"
	EventAfterChangeEmail                 EventType = "after:change-email"
	EventBeforeChangePhone                EventType = "before:change-phone"
	EventAfterChangePhone                 EventType = "after:change-phone"
	EventBeforeChangeUsername             EventType = "before:change-username"
	EventAfterChangeUsername              EventType = "after:change-username"
	EventBeforeChangeProfile              EventType = "before:change-profile"
	EventAfterChangeProfile               EventType = "after:change-profile"
	EventBeforeChangeAvatar               EventType = "before:change-avatar"
	EventAfterChangeAvatar                EventType = "after:change-avatar"
	EventBeforeChangeBio                  EventType = "before:change-bio"
	EventAfterChangeBio                   EventType = "after:change-bio"
	EventBeforeChangeName                 EventType = "before:change-name"
	EventAfterChangeName                  EventType = "after:change-name"
	EventBeforeChangeEmailVerification    EventType = "before:change-email-verification"
	EventAfterChangeEmailVerification     EventType = "after:change-email-verification"
	EventBeforeChangePhoneVerification    EventType = "before:change-phone-verification"
	EventAfterChangePhoneVerification     EventType = "after:change-phone-verification"
	EventBeforeChangeUsernameVerification EventType = "before:change-username-verification"
	EventAfterChangeUsernameVerification  EventType = "after:change-username-verification"
	EventBeforeChangeProfileVerification  EventType = "before:change-profile-verification"
	EventAfterChangeProfileVerification   EventType = "after:change-profile-verification"
	EventBeforeChangeAvatarVerification   EventType = "before:change-avatar-verification"
	EventAfterChangeAvatarVerification    EventType = "after:change-avatar-verification"
	EventAdminAction                      EventType = "admin:action"
)
