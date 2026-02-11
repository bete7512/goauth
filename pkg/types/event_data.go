package types

import (
	"encoding/json"
	"time"

	"github.com/bete7512/goauth/pkg/models"
)

// RequestMetadata contains typed HTTP request context for events.
// Replaces map[string]interface{} for metadata in event emission.
type RequestMetadata struct {
	IPAddress         string    `json:"ip_address"`
	ForwardedFor      string    `json:"forwarded_for,omitempty"`
	UserAgent         string    `json:"user_agent"`
	Referer           string    `json:"referer,omitempty"`
	Host              string    `json:"host,omitempty"`
	Timestamp         time.Time `json:"timestamp"`
	RequestID         string    `json:"request_id,omitempty"`
	DeviceFingerprint string    `json:"device_fingerprint,omitempty"`
}

// BeforeHookData is used for before:* events (before:signup, before:login, etc.)
// The Body field is interface{} because it varies by module (SignupRequest, LoginRequest, etc.)
type BeforeHookData struct {
	Body     interface{}      `json:"body"`
	Metadata *RequestMetadata `json:"metadata"`
}

// UserEventData is used for events that carry user information.
// Used by: after:signup, send:email-verification, send:phone-verification,
// after:email-verified, after:reset-password
type UserEventData struct {
	User     *models.User     `json:"user"`
	Metadata *RequestMetadata `json:"metadata,omitempty"`
}

// LoginEventData is used for after:login events.
// Includes the user, optional session data, and request metadata.
type LoginEventData struct {
	User     *models.User     `json:"user"`
	Session  interface{}      `json:"session,omitempty"`
	Metadata *RequestMetadata `json:"metadata"`
}

// LogoutEventData is used for after:logout events.
type LogoutEventData struct {
	UserID string `json:"user_id"`
}

// EmailVerificationRequestData is used for send:email-verification events.
// Carries the pre-built verification link so notification just renders + delivers.
type EmailVerificationRequestData struct {
	User             *models.User `json:"user"`
	VerificationLink string       `json:"verification_link"`
}

// PhoneVerificationRequestData is used for send:phone-verification events.
// Carries the OTP code so notification just renders + delivers.
type PhoneVerificationRequestData struct {
	User       *models.User `json:"user"`
	Code       string       `json:"code"`
	ExpiryTime string       `json:"expiry_time"`
}

// PasswordResetRequestData is used for send:password-reset-email events.
// Contains the reset link and code for notification handlers.
type PasswordResetRequestData struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number,omitempty"`
	Name        string `json:"name"`
	ResetLink   string `json:"reset_link"`
	Code        string `json:"code"`
}

// PasswordChangedData is used for after:change-password and after:reset-password events.
type PasswordChangedData struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Timestamp time.Time `json:"timestamp"`
}

// ProfileChangedData is used for after:change-profile events.
type ProfileChangedData struct {
	UserID string   `json:"user_id"`
	Fields []string `json:"fields"`
}

// MagicLinkRequestData is used for send.magic-link events.
// Contains the pre-built magic link and OTP code for notification handlers.
type MagicLinkRequestData struct {
	User       *models.User `json:"user"`
	MagicLink  string       `json:"magic_link"`
	Code       string       `json:"code,omitempty"`
	ExpiryTime string       `json:"expiry_time"`
}

// EventDataAs extracts typed event data from an Event.
// Returns the typed data and true if the assertion succeeds.
//
// Supports two modes:
//   - Direct type assertion (in-process backends like worker pool)
//   - JSON deserialization (serialized backends like NATS JetStream, Redis)
//
// Usage:
//
//	data, ok := types.EventDataAs[*types.UserEventData](event)
//	if !ok {
//	    return fmt.Errorf("unexpected event data type")
//	}
//	user := data.User
func EventDataAs[T any](event *Event) (T, bool) {
	// Direct type assertion (in-process backends)
	if data, ok := event.Data.(T); ok {
		return data, ok
	}

	// JSON deserialization (serialized backends)
	var raw []byte
	switch v := event.Data.(type) {
	case json.RawMessage:
		raw = v
	case []byte:
		raw = v
	default:
		var zero T
		return zero, false
	}

	var data T
	if err := json.Unmarshal(raw, &data); err != nil {
		var zero T
		return zero, false
	}
	return data, true
}
