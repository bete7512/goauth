package types

//go:generate mockgen -destination=../../internal/mocks/mock_events.go -package=mocks github.com/bete7512/goauth/pkg/types EventBus,AsyncBackend

import (
	"context"
	"time"
)

type EventType string

// Event represents an event with associated data, identity, and retry tracking.
type Event struct {
	// ID uniquely identifies this event instance (for idempotency and tracking)
	ID string

	// Type is the event type (e.g. "after:signup")
	Type EventType

	// Context is the event context
	Context context.Context

	// Data is the event payload. Use typed event data structs from event_data.go
	// (e.g. *UserEventData, *LoginEventData) for type safety.
	Data interface{}

	// Error holds any error that occurred during event processing
	Error error

	// CreatedAt is when the event was created
	CreatedAt time.Time

	// RetryCount tracks how many times this event has been retried
	RetryCount int

	// MaxRetries is the maximum number of retries allowed for this event
	MaxRetries int
}

// RetryPolicy configures retry behavior for event handlers.
type RetryPolicy struct {
	// MaxRetries is the maximum number of retry attempts (0 = no retry)
	MaxRetries int

	// InitialBackoff is the delay before the first retry
	InitialBackoff time.Duration

	// MaxBackoff caps the backoff duration
	MaxBackoff time.Duration

	// BackoffMultiplier multiplies the backoff after each retry (e.g. 2.0 for exponential)
	BackoffMultiplier float64
}

// DefaultRetryPolicy returns a sensible default retry policy.
// 3 retries with exponential backoff: 1s → 2s → 4s
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxRetries:        3,
		InitialBackoff:    1 * time.Second,
		MaxBackoff:        30 * time.Second,
		BackoffMultiplier: 2.0,
	}
}

// EventBus interface for event handling
type EventBus interface {
	Subscribe(eventType EventType, handler EventHandler, opts ...interface{})
	EmitAsync(ctx context.Context, eventType EventType, data interface{}) error
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
	// Hook Events
	EventBeforeSignup                     EventType = "before:signup"
	EventAfterSignup                      EventType = "after:signup"
	EventAfterEmailVerified               EventType = "after:email-verified"
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

	// Authentication Events (for audit logging)
	EventAuthLoginSuccess    EventType = "auth:login:success"
	EventAuthLoginFailed     EventType = "auth:login:failed"
	EventAuthLogout          EventType = "auth:logout"
	EventAuthPasswordChanged EventType = "auth:password:changed"
	EventAuth2FAEnabled      EventType = "auth:2fa:enabled"
	EventAuth2FADisabled     EventType = "auth:2fa:disabled"

	// User Profile Events (for audit logging)
	EventUserProfileUpdated EventType = "user:profile:updated"
	EventUserEmailChanged   EventType = "user:email:changed"
	EventUserEmailVerified  EventType = "user:email:verified"
	EventUserPhoneChanged   EventType = "user:phone:changed"
	EventUserAvatarUpdated  EventType = "user:avatar:updated"

	// Admin Events (for audit logging)
	EventAdminUserCreated   EventType = "admin:user:created"
	EventAdminUserUpdated   EventType = "admin:user:updated"
	EventAdminUserDeleted   EventType = "admin:user:deleted"
	EventAdminUserSuspended EventType = "admin:user:suspended"
	EventAdminRoleAssigned  EventType = "admin:role:assigned"
	EventAdminRoleRevoked   EventType = "admin:role:revoked"

	// Security Events (for audit logging)
	EventSecuritySuspiciousLogin EventType = "security:suspicious:login"
	EventSecurityAccountLocked   EventType = "security:account:locked"
	EventSecuritySessionRevoked  EventType = "security:session:revoked"
	EventSecurityTokenInvalidated EventType = "security:token:invalidated"

	// Action Events
	EventSendEmailVerification  EventType = "send:email-verification"
	EventSendPhoneVerification  EventType = "send:phone-verification"
	EventSendPasswordResetEmail EventType = "send:password-reset-email"
)
