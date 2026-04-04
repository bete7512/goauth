package types

import (
	"net/http"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/golang-jwt/jwt/v5"
)

type SessionConfig struct {
	Name            string
	SessionTTL      time.Duration
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	Secure          bool
	HttpOnly        bool
	SameSite        http.SameSite
	Domain          string
	Path            string
	MaxAge          int
}

// AuthMode defines the authentication mode for the application
type AuthMode string

const (
	AuthModeCookie AuthMode = "cookie" // Cookie-based authentication only
	AuthModeBearer AuthMode = "bearer" // Bearer token authentication only
	AuthModeBoth   AuthMode = "both"   // Both cookie and bearer token (default)
	AuthModeCustom AuthMode = "custom" // Custom authentication schemes
)

type SecurityConfig struct {
	JwtSecretKey         string
	EncryptionKey        string
	HashSaltLength       int
	CustomClaimsProvider CustomClaimsProvider
	Session              SessionConfig
	PasswordPolicy       PasswordPolicy
	Lockout              LockoutConfig
	AuthMode             AuthMode // Authentication mode (cookie, bearer, both, custom)
	AuthStrategy         AuthStrategy
}

// LockoutConfig controls account lockout after repeated failed login attempts.
type LockoutConfig struct {
	Enabled         bool          // Whether lockout is enabled (default: true)
	MaxAttempts     int           // Failed attempts before locking (default: 5)
	LockoutDuration time.Duration // How long the account stays locked (default: 15m)
}

// AuthStrategy determines the authentication strategy
type AuthStrategy string

const (
	StrategySession   AuthStrategy = "session"   // Default stateful session
	StrategyStateless AuthStrategy = "stateless" // JWT-only stateless
)

type PasswordPolicy struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumbers   bool
	RequireSpecial   bool
}

type CustomClaimsProvider interface {
	GetClaims(user *models.User) (jwt.MapClaims, error)
}
