package config

import (
	"context"
	"net/http"
	"time"

	// "github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/types"
)

type RouteInfo struct {
	Name        string // Unique route identifier (e.g., "core.login", "admin.users.list")
	Method      string
	Path        string
	Handler     http.HandlerFunc
	Middlewares []types.MiddlewareName
}

type ModuleMigration struct {
	ID   string
	Up   string
	Down string
}

type Module interface {
	// Name returns the module identifier
	Name() string

	// Init initializes the module with dependencies
	Init(ctx context.Context, deps ModuleDependencies) error

	// Routes returns HTTP routes with unique names
	Routes() []RouteInfo

	// Middlewares returns middleware configurations for this module
	Middlewares() []MiddlewareConfig

	// Models returns database models for migration
	Models() []interface{}

	// RegisterHooks registers event handlers for this module
	RegisterHooks(events types.EventBus) error

	// Dependencies returns required module names
	Dependencies() []string

	// SwaggerSpec returns module's swagger spec (YAML or JSON)
	SwaggerSpec() []byte // Returns module's swagger spec (YAML or JSON)

}

type ModuleDependencies struct {
	Storage           Storage
	Config            *Config
	Logger            logger.Logger
	Events            types.EventBus
	MiddlewareManager MiddlewareManager
	SecurityManager   *security.SecurityManager
	Options           interface{}
}

// MiddlewareConfig for modules to define middleware application
type MiddlewareConfig struct {
	Name        types.MiddlewareName
	Middleware  func(http.Handler) http.Handler
	Priority    int
	ApplyTo     []types.RouteName // Route names or patterns (e.g. types.RouteSignup, "core.*")
	ExcludeFrom []types.RouteName // Route names or patterns to exclude
	Global      bool              // Apply to all routes
}

// MiddlewareManager manages middleware application
type MiddlewareManager interface {
	Apply(routeName string, handler http.Handler) http.Handler
	ApplyGlobal(handler http.Handler) http.Handler
}

type Config struct {
	// Storage backend
	Storage Storage

	// Migration
	AutoMigrate bool

	// Base path for all routes
	BasePath string

	// Module-specific configurations
	ModuleConfigs map[string]interface{}

	// Logger - Users can provide their own logger implementation
	// If nil, a default logrus logger will be used
	Logger *logger.LogrusLogger

	// CORS Configuration
	CORS *CORSConfig

	// AsyncBackend for async event processing
	// If nil, uses default worker pool (10 workers, 1000 queue size)
	// Users can provide Redis, RabbitMQ, Kafka, or custom implementations
	AsyncBackend types.AsyncBackend

	// Security
	Security types.SecurityConfig

	// Core Config
	Core *CoreConfig

	// app config
	FrontendConfig *FrontendConfig

	// Domain
	APIURL string
}

type FrontendConfig struct {
	Domain                  string
	URL                     string
	ResetPasswordPath       string
	VerifyEmailCallbackPath string
	LoginPath               string
	SignupPath              string
	LogoutPath              string
	ProfilePath             string
	ChangePasswordPath      string
}

type CoreConfig struct {
	RequirePhoneNumber       bool
	RequireUserName          bool
	RequireEmailVerification bool
	RequirePhoneVerification bool
	UniquePhoneNumber        bool
}

// SessionModuleConfig holds configuration for session-based authentication module
type SessionModuleConfig struct {
	// EnableSessionManagement enables session management endpoints (list, delete sessions)
	EnableSessionManagement bool

	// Strategy controls how sessions are validated per-request.
	// "database" (default): JWT-only validation, session DB used only for refresh/logout.
	// "cookie_cache": Signed session cookie for revocation checks without DB round-trip.
	Strategy types.SessionStrategy

	// CookieEncoding determines encoding format for session cookies.
	// "compact" (default): base64url(JSON) + "." + HMAC-SHA256 (~200 bytes).
	// "jwt": Standard HS256 JWT (~400 bytes, interoperable).
	CookieEncoding types.CookieEncoding

	// CookieCacheTTL controls how long the session cookie is trusted before
	// requiring a DB re-validation. Default: 5 minutes.
	// Only used when Strategy is SessionStrategyCookieCache.
	CookieCacheTTL time.Duration

	// SensitivePaths are route path patterns that always validate against DB,
	// even when cookie cache is valid. Supports wildcard patterns (e.g., "/admin/*").
	SensitivePaths []string

	// SlidingExpiration extends the session ExpiresAt in the DB when the user
	// is active and the session is in the extension window. Default: false.
	SlidingExpiration bool

	// UpdateAge forces a DB re-validation when this duration has passed since
	// the cookie was last issued. Also defines the extension window threshold
	// for sliding expiration (window = UpdateAge/2). Default: 10 minutes.
	UpdateAge time.Duration
}

// StatelessModuleConfig holds configuration for stateless JWT authentication module
type StatelessModuleConfig struct {
	// RefreshTokenRotation enables refresh token rotation on each refresh
	RefreshTokenRotation bool
}

// CSRFModuleConfig holds configuration for CSRF protection module
type CSRFModuleConfig struct {
	// TokenExpiry is how long CSRF tokens remain valid (default: 1 hour)
	TokenExpiry time.Duration

	// CookieName is the name of the CSRF cookie (default: "__goauth_csrf")
	CookieName string

	// HeaderName is the HTTP header clients send the token in (default: "X-CSRF-Token")
	HeaderName string

	// FormFieldName is the form field name for the token (default: "csrf_token")
	FormFieldName string

	// Secure sets the Secure flag on the CSRF cookie (default: true)
	Secure bool

	// SameSite sets the SameSite attribute on the CSRF cookie (default: Lax)
	SameSite http.SameSite

	// CookiePath sets the Path attribute on the CSRF cookie (default: "/")
	CookiePath string

	// CookieDomain sets the Domain attribute on the CSRF cookie (default: "")
	CookieDomain string

	// ExcludePaths are URL path prefixes that skip CSRF validation
	ExcludePaths []string

	// ProtectedMethods are HTTP methods that require CSRF validation (default: POST, PUT, DELETE, PATCH)
	ProtectedMethods []string
}

// CaptchaModuleConfig holds configuration for CAPTCHA verification module
type CaptchaModuleConfig struct {
	// Provider is the captcha provider: types.CaptchaProviderGoogle or types.CaptchaProviderCloudflare
	Provider types.CaptchaProvider

	// SiteKey is the public site key from the provider (used by frontend widget)
	SiteKey string

	// SecretKey is the server-side secret key from the provider
	SecretKey string

	// ScoreThreshold is the minimum score for Google reCAPTCHA v3 (0.0-1.0, default: 0.5)
	// Ignored for Cloudflare Turnstile which uses binary pass/fail
	ScoreThreshold float64

	// VerifyTimeout is the HTTP timeout for provider API calls (default: 10s)
	VerifyTimeout time.Duration

	// HeaderName is the HTTP header to read the captcha token from (default: "X-Captcha-Token")
	HeaderName string

	// FormFieldName is the form field fallback for the captcha token (default: "captcha_token")
	FormFieldName string

	// ApplyToRoutes are route names or patterns that require captcha (e.g. types.RouteSignup, types.RouteLogin)
	ApplyToRoutes []types.RouteName

	// ExcludeRoutes are route names or patterns to exclude from captcha
	ExcludeRoutes []types.RouteName
}

// MagicLinkModuleConfig holds configuration for magic link passwordless authentication
type MagicLinkModuleConfig struct {
	// TokenExpiry is how long magic link tokens remain valid (default: 15 minutes)
	TokenExpiry time.Duration

	// AutoRegister creates a new user if the email doesn't exist (default: false)
	AutoRegister bool

	// CallbackURL is the frontend URL to redirect to after verification.
	// Tokens are passed as URL fragment: CallbackURL#access_token=xxx&refresh_token=xxx
	// If empty, the verify endpoint returns JSON AuthResponse instead.
	CallbackURL string
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	Enabled          bool
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowCredentials bool
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Storage == nil {
		return ErrConfig("storage backend is required")
	}
	if c.Security.JwtSecretKey == "" {
		return ErrConfig("jwt secret key is required")
	}
	if c.Security.EncryptionKey == "" {
		return ErrConfig("encryption key is required")
	}
	if c.Security.HashSaltLength <= 0 {
		c.Security.HashSaltLength = 10 // Default to 10
	}
	if c.Security.Session.SessionTTL <= 0 {
		c.Security.Session.SessionTTL = 30 * 24 * time.Hour // Default to 24 hours
	}
	if c.Security.Session.RefreshTokenTTL <= 0 {
		c.Security.Session.RefreshTokenTTL = 7 * 24 * time.Hour // Default to 7 days
	}
	if c.BasePath == "" {
		c.BasePath = "/auth"
	}
	if c.ModuleConfigs == nil {
		c.ModuleConfigs = make(map[string]interface{})
	}

	// Set default CORS if not provided
	if c.CORS == nil {
		c.CORS = &CORSConfig{
			Enabled:          false,
			
		}
	}

	return nil
}

func (c *Config) GetModuleConfig(name string) interface{} {
	return c.ModuleConfigs[name]
}
