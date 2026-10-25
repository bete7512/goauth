package types

import (
	"net/http"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/golang-jwt/jwt/v5"
)

// SessionConfig configures credential lifetimes and cookies.
type SessionConfig struct {
	Name            string
	SessionTTL      time.Duration
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	// AllowInsecureCookies issues cookies without the Secure attribute, for
	// local development over plain HTTP only. Every cookie GoAuth sets is
	// Secure unless this is true, and Initialize logs a warning when it is.
	AllowInsecureCookies bool
	// Secure is set by config validation to !AllowInsecureCookies; any value
	// assigned by the host is overwritten. Use AllowInsecureCookies instead.
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
	Domain   string
	Path     string
	MaxAge   int
}

// AuthMode defines the authentication mode for the application
type AuthMode string

// Credential transports.
const (
	AuthModeCookie AuthMode = "cookie" // Cookie-based authentication only
	AuthModeBearer AuthMode = "bearer" // Bearer token authentication only
	AuthModeBoth   AuthMode = "both"   // Both cookie and bearer token (default)
	AuthModeCustom AuthMode = "custom" // Custom authentication schemes
)

// SecurityConfig holds secrets, signing keys, credential lifetimes, and the
// password, lockout and cookie policies.
type SecurityConfig struct {
	// RetainedJWTKeys are verification-only keys kept during a rotation window.
	RetainedJWTKeys []JWTVerificationKey
	EncryptionKeyID string
	DecryptionKeys  map[string]string
	// JWTIssuer and JWTAudience identify this application's credentials.
	// Empty values use "goauth"; deployments sharing keys must set distinct values.
	JWTIssuer            string
	JWTAudience          string
	JwtSecretKey         string
	EncryptionKey        string
	HashSaltLength       int
	CustomClaimsProvider CustomClaimsProvider
	Session              SessionConfig
	PasswordPolicy       PasswordPolicy
	Lockout              LockoutConfig
	AuthMode             AuthMode // Authentication mode (cookie, bearer, both, custom)
	AuthStrategy         AuthStrategy

	// JWTAlgorithm is the JWT signing algorithm. Default: HS256 (symmetric,
	// uses JwtSecretKey). Set to RS256 or ES256 to use asymmetric keys —
	// consumers (gateways, microservices) can then verify tokens via the
	// public JWKS endpoint without sharing a secret.
	JWTAlgorithm JWTAlgorithm

	// JWTPrivateKeyPEM is the PEM-encoded private key used for signing.
	// Required when JWTAlgorithm is RS256 or ES256. Takes precedence over JWTPrivateKeyFile.
	JWTPrivateKeyPEM []byte

	// JWTPrivateKeyFile is a filesystem path to a PEM-encoded private key.
	// Used when JWTPrivateKeyPEM is empty and JWTAlgorithm is asymmetric.
	JWTPrivateKeyFile string

	// JWTPublicKeyPEM is the PEM-encoded public key served at /.well-known/jwks.json.
	// Optional — if empty, the public key is derived from the private key.
	JWTPublicKeyPEM []byte

	// JWTPublicKeyFile is a filesystem path to a PEM-encoded public key.
	// Used when JWTPublicKeyPEM is empty.
	JWTPublicKeyFile string

	// JWTKeyID is the value set in the JWT "kid" header and JWKS entry.
	// If empty, a deterministic fingerprint of the public key is used.
	JWTKeyID string
}

// JWTVerificationKey is a retired signing key kept to verify tokens issued
// before a rotation, until NotAfter.
type JWTVerificationKey struct {
	ID           string
	Algorithm    JWTAlgorithm
	PublicKeyPEM []byte
	Secret       string
	NotAfter     time.Time
}

// LockoutConfig controls account lockout after repeated failed login attempts.
type LockoutConfig struct {
	// Disabled explicitly opts out; an omitted configuration enables lockout.
	Disabled        bool
	Enabled         bool          // Whether lockout is enabled (default: true)
	MaxAttempts     int           // Failed attempts before locking (default: 5)
	LockoutDuration time.Duration // How long the account stays locked (default: 15m)
	// RevealLocked answers a locked account with ACCOUNT_LOCKED (423) instead
	// of the generic INVALID_CREDENTIALS. Off by default: a visible lock
	// confirms that the account exists and tells an attacker the lock worked.
	RevealLocked bool
}

// AuthStrategy determines the authentication strategy
type AuthStrategy string

// Authentication strategies.
const (
	StrategySession   AuthStrategy = "session"   // Default stateful session
	StrategyStateless AuthStrategy = "stateless" // JWT-only stateless
)

// PasswordPolicy constrains new passwords. Lengths count bytes, and the
// maximum is capped at 72, the bcrypt input limit.
type PasswordPolicy struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumbers   bool
	RequireSpecial   bool
}

// CustomClaimsProvider adds application claims to issued access tokens.
// Reserved identity, purpose and lifetime claims cannot be overridden.
type CustomClaimsProvider interface {
	GetClaims(user *models.User) (jwt.MapClaims, error)
}
