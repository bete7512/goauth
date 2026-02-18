package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bete7512/goauth/internal/security/cookie"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

var (
	ErrSessionRevoked = errors.New("session has been revoked")
)

// ValidationResult is the outcome of a session validation attempt.
type ValidationResult struct {
	Valid         bool   // Whether the session is currently valid
	SessionID     string // Extracted session ID
	UserID        string // Extracted user ID
	ShouldRefresh bool   // True when the session cookie should be re-issued
	Source        string // "cookie" or "database"
	Error         error  // Non-nil when Valid is false
}

// ValidatorConfig holds configuration for the SessionValidator.
type ValidatorConfig struct {
	CacheTTL          time.Duration // How long the cookie is trusted before DB re-check
	SessionTTL        time.Duration // Full session lifetime (for sliding extension)
	SensitivePaths    []string      // Path patterns that always check DB
	SlidingExpiration bool          // Extend session ExpiresAt on activity
	UpdateAge         time.Duration // Force DB re-validation after this duration since cookie was issued
}

// SessionValidator validates sessions using cookie cache with DB fallback.
type SessionValidator struct {
	encoder     cookie.CookieEncoder
	sessionRepo models.SessionRepository
	config      ValidatorConfig
}

// NewSessionValidator creates a validator with the given dependencies.
func NewSessionValidator(
	encoder cookie.CookieEncoder,
	repo models.SessionRepository,
	cfg ValidatorConfig,
) *SessionValidator {
	return &SessionValidator{
		encoder:     encoder,
		sessionRepo: repo,
		config:      cfg,
	}
}

// ValidateFromCookie decodes the session cookie and checks validity.
// When the cookie is invalid/expired/missing, returns Valid=false and ShouldRefresh=true
// so the caller can fall back to DB.
func (v *SessionValidator) ValidateFromCookie(cookieValue string) ValidationResult {
	if cookieValue == "" {
		return ValidationResult{ShouldRefresh: true, Error: cookie.ErrInvalidFormat}
	}

	data, err := v.encoder.Decode(cookieValue)
	if err != nil {
		return ValidationResult{ShouldRefresh: true, Error: err}
	}

	result := ValidationResult{
		Valid:     true,
		SessionID: data.SessionID,
		UserID:    data.UserID,
		Source:    "cookie",
	}

	// UpdateAge: if the cookie was issued too long ago, force a DB re-check.
	if v.config.UpdateAge > 0 {
		issuedAt := time.Unix(data.IssuedAt, 0)
		if time.Since(issuedAt) > v.config.UpdateAge {
			result.ShouldRefresh = true
			result.Valid = false // Don't trust a stale cookie
		}
	}

	return result
}

// ValidateFromDB checks the session exists and is not expired in the database.
// If SlidingExpiration is enabled and the session is in the extension window
// (time until expiry < UpdateAge/2), it extends ExpiresAt by SessionTTL.
// Always sets ShouldRefresh=true so the caller re-issues the session cookie.
func (v *SessionValidator) ValidateFromDB(ctx context.Context, sessionID string) ValidationResult {
	session, err := v.sessionRepo.FindByID(ctx, sessionID)
	if err != nil || session == nil {
		return ValidationResult{Error: ErrSessionRevoked}
	}

	if session.ExpiresAt.Before(time.Now()) {
		return ValidationResult{Error: ErrSessionRevoked}
	}

	result := ValidationResult{
		Valid:         true,
		SessionID:     session.ID,
		UserID:        session.UserID,
		ShouldRefresh: true, // Always re-issue cookie after DB validation
		Source:        "database",
	}

	// Sliding expiration: extend session if in extension window
	if v.config.SlidingExpiration && v.config.UpdateAge > 0 && v.config.SessionTTL > 0 {
		extensionThreshold := v.config.UpdateAge / 2
		timeUntilExpiry := time.Until(session.ExpiresAt)
		if timeUntilExpiry < extensionThreshold {
			session.ExpiresAt = time.Now().Add(v.config.SessionTTL)
			session.UpdatedAt = time.Now()
			// Best-effort update; don't fail the request if this fails
			_ = v.sessionRepo.Update(ctx, session)
		}
	}

	return result
}

// BuildCookieValue creates a new signed session cookie value.
func (v *SessionValidator) BuildCookieValue(sessionID, userID string) (string, error) {
	now := time.Now()
	data := &types.SessionCookieData{
		SessionID: sessionID,
		UserID:    userID,
		ExpiresAt: now.Add(v.config.CacheTTL).Unix(),
		IssuedAt:  now.Unix(),
	}
	return v.encoder.Encode(data)
}

// IsSensitivePath checks if the request path matches any sensitive patterns.
// Supports trailing wildcard: "/admin/*" matches "/admin/users", "/admin/users/123".
func (v *SessionValidator) IsSensitivePath(path string) bool {
	for _, pattern := range v.config.SensitivePaths {
		if matchPath(pattern, path) {
			return true
		}
	}
	return false
}

// CacheTTL returns the configured cache TTL.
func (v *SessionValidator) CacheTTL() time.Duration {
	return v.config.CacheTTL
}

func matchPath(pattern, path string) bool {
	if pattern == path {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	}
	return false
}
