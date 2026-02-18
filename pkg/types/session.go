package types

// SessionStrategy controls how sessions are validated per-request.
type SessionStrategy string

const (
	// SessionStrategyDatabase is the default: JWT-only validation,
	// session DB used only for refresh/logout. No per-request revocation check.
	SessionStrategyDatabase SessionStrategy = "database"

	// SessionStrategyCookieCache embeds signed session data in a cookie
	// for revocation checks without a DB round-trip on every request.
	SessionStrategyCookieCache SessionStrategy = "cookie_cache"
)

// CookieEncoding determines the encoding format for session cookies.
type CookieEncoding string

const (
	// CookieEncodingCompact uses base64url(JSON) + "." + HMAC-SHA256. Smallest (~200 bytes).
	CookieEncodingCompact CookieEncoding = "compact"

	// CookieEncodingJWT uses standard HS256 JWT format. Interoperable (~400 bytes).
	CookieEncodingJWT CookieEncoding = "jwt"
)

// SessionCookieData is the subset of session data embedded in the signed cookie.
// RefreshToken is intentionally excluded — it must never appear in a cookie payload.
type SessionCookieData struct {
	SessionID string `json:"sid"`
	UserID    string `json:"uid"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
}
