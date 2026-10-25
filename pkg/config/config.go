package config

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/types"
)

type RouteInfo struct {
	Name        string // Unique route identifier (e.g., "core.login", "admin.users.list")
	Method      string
	Path        string
	Handler     http.HandlerFunc
	Middlewares []types.MiddlewareName
}

// MigrationConfig controls the module migration system.
type MigrationConfig struct {
	// Auto: apply pending module migrations during Initialize().
	Auto bool

	// OutputDir: write up/down SQL files for all modules to this directory during Initialize().
	// Files are named: {module}_{dialect}_up.sql and {module}_{dialect}_down.sql
	// Can be combined with Auto (generates files AND applies them).
	OutputDir string
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

	// RegisterHooks registers event handlers for this module
	RegisterHooks(events types.EventBus) error

	// Dependencies returns required module names
	Dependencies() []string

	// OpenAPISpecs returns module's openapi specs
	OpenAPISpecs() []byte

	// Migrations returns per-dialect SQL migration files (up and down).
	// Modules with no DB tables should return an empty types.ModuleMigrations{}.
	Migrations() types.ModuleMigrations
}

type ModuleDependencies struct {
	Completion        types.AuthenticationCompleter
	Storage           types.Storage
	Config            *Config
	Logger            types.Logger
	Events            types.EventBus
	MiddlewareManager MiddlewareManager
	SecurityManager   types.SecurityManager
	AuthInterceptors  types.AuthInterceptorRegistry
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
	MaxConcurrentRequests int
	Admission             types.AdmissionController
	Observer              types.OperationObserver
	// DurableEvents records authentication completion in the credential transaction.
	// Requires colocated TransactionalStorage and OutboxStore capabilities.
	DurableEvents bool
	// SecurityManager optionally replaces the shared cryptographic service.
	SecurityManager types.SecurityManager
	// BorrowStorage leaves application-owned storage open during shutdown.
	BorrowStorage bool
	// MaxRequestBodyBytes bounds built-in HTTP request bodies. Default: 1 MiB.
	MaxRequestBodyBytes int64
	// Storage backend
	Storage types.Storage

	// Migration: module migration system with per-dialect SQL files and a tracking table.
	Migration MigrationConfig

	// Base path for all routes
	BasePath string

	// Module-specific configurations
	ModuleConfigs map[string]interface{}

	// Logger - Users can provide their own logger implementation (types.Logger).
	// If nil, a default logrus logger will be used.
	Logger types.Logger

	// AsyncBackend for async event processing
	// If nil, uses default worker pool (10 workers, 1000 queue size)
	// Users can provide Redis, RabbitMQ, Kafka, or custom implementations
	AsyncBackend types.AsyncBackend

	// Security
	Security types.SecurityConfig

	// Core Config
	Core *CoreConfig

	// RateLimit configures the built-in request rate limiter. Initialize
	// registers it with these settings (nil means the default rules and an
	// in-memory store) unless Disabled is set or a ratelimit module was
	// registered explicitly with Use.
	RateLimit *RateLimitModuleConfig

	// TrustedProxies lists reverse proxies, as IPs or CIDR blocks, whose
	// X-Forwarded-For and X-Real-IP headers may be trusted to carry the client
	// address. Leave empty when clients connect directly.
	TrustedProxies []string

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

	// CustomStorage is optional. If nil, storage is obtained from deps.Storage.Core() during Init.
	CustomStorage types.CoreStorage
}

// SessionModuleConfig holds configuration for session-based authentication module
type SessionModuleConfig struct {
	// CustomStorage is optional. If nil, storage is obtained from deps.Storage.Session() during Init.
	CustomStorage types.SessionStorage

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
	// CustomStorage is optional. If nil, storage is obtained from deps.Storage.Core() during Init.
	CustomStorage types.CoreStorage

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
// RateLimitRuleConfig is one rate-limit rule applied to matching routes.
type RateLimitRuleConfig struct {
	// Name identifies the rule in headers, events and logs. Required and unique.
	Name string

	// ApplyTo lists route names or patterns, e.g. types.RouteLogin or "core.*".
	ApplyTo []types.RouteName

	// ExcludeFrom lists route names or patterns exempt from this rule.
	ExcludeFrom []types.RouteName

	// Key selects what is counted: types.RateLimitKeyIP (default),
	// types.RateLimitKeyIdentifier or types.RateLimitKeyIPIdentifier.
	Key types.RateLimitKey

	// Limit is the number of requests allowed per Window.
	Limit int

	// Window is the period over which Limit applies.
	Window time.Duration

	// Burst bounds back-to-back requests. Zero means Limit.
	Burst int
}

// RateLimitModuleConfig configures the built-in rate limiter. The zero value
// (or a nil pointer in Config) enables the default rules with a memory store.
type RateLimitModuleConfig struct {
	// Disabled turns rate limiting off entirely.
	Disabled bool

	// Store keeps the counters. Nil selects a process-local memory store;
	// provide a shared implementation (for example Redis) when running
	// several replicas so budgets are enforced across them.
	Store types.RateLimitStore

	// Rules replaces the default rule set when non-nil.
	Rules []RateLimitRuleConfig

	// ExtraRules are appended to the active rule set.
	ExtraRules []RateLimitRuleConfig

	// Allowlist lists IPs or CIDR blocks that are never limited, such as
	// health checkers or an office egress address.
	Allowlist []string

	// FailClosed rejects requests with 503 when the store fails. By default a
	// store failure lets requests through and is logged.
	FailClosed bool

	// IPv6PrefixBits buckets IPv6 clients by network prefix. Default: 64.
	IPv6PrefixBits int

	// DisableHeaders suppresses the RateLimit-Limit, RateLimit-Remaining and
	// RateLimit-Reset response headers. Retry-After is always sent on 429.
	DisableHeaders bool

	// MaxTrackedKeys caps the memory store. Default: 100000.
	MaxTrackedKeys int
}

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

// MagicLinkModuleConfig holds configuration for magic link / email OTP passwordless authentication
type MagicLinkModuleConfig struct {
	// CustomStorage is optional. If nil, storage is obtained from deps.Storage.Core() during Init.
	CustomStorage types.CoreStorage

	// TokenExpiry is how long magic link tokens / email OTP codes remain valid.
	// Default: 10 minutes.
	TokenExpiry time.Duration

	// AutoRegister creates a new user if the email doesn't exist (default: false)
	AutoRegister bool

	// CallbackURL is the frontend URL to redirect to after verification.
	// Tokens are passed as URL fragment: CallbackURL#access_token=xxx&refresh_token=xxx
	// If empty, the verify endpoint returns JSON AuthResponse instead.
	CallbackURL string

	// DeliveryMode controls what the email contains:
	//   - MagicLinkDeliveryModeLink: link-only (classic magic link)
	//   - MagicLinkDeliveryModeCode: 6-digit code only (email OTP)
	//   - MagicLinkDeliveryModeBoth: both link and code (default)
	DeliveryMode types.MagicLinkDeliveryMode

	// MaxCodeAttempts is the maximum number of /verify-code attempts per issued code.
	// When exceeded, the code is invalidated and the user must request a new one.
	// Default: 5.
	MaxCodeAttempts int
}

// PasskeysModuleConfig holds configuration for the WebAuthn/Passkeys module.
type PasskeysModuleConfig struct {
	// CustomStorage is optional. If nil, storage is obtained from deps.Storage.Passkeys() during Init.
	CustomStorage types.PasskeyStorage

	// RPDisplayName is the human-readable Relying Party name shown to users by
	// the authenticator (e.g. in the OS passkey picker). Defaults to "GoAuth".
	RPDisplayName string

	// RPID is the WebAuthn Relying Party ID — usually the apex domain without
	// scheme or port (e.g. "example.com"). Must be derivable from the origin.
	// Required.
	RPID string

	// RPOrigins is the list of allowed origins (e.g. "https://app.example.com").
	// The authenticator response must come from one of these origins.
	// At least one required.
	RPOrigins []string

	// ChallengeTTL is how long a begin→finish ceremony window remains valid.
	// Default: 5 minutes.
	ChallengeTTL time.Duration
}

// OAuthModuleConfig holds configuration for OAuth authentication module
type OAuthModuleConfig struct {
	// CustomCoreStorage is optional. If nil, uses deps.Storage.Core() during Init.
	CustomCoreStorage types.CoreStorage
	// CustomOAuthStorage is optional. If nil, uses deps.Storage.OAuth() during Init.
	CustomOAuthStorage types.OAuthStorage
	// CustomSessionStorage is optional. For session-based auth; if nil uses deps.Storage.Session() during Init.
	CustomSessionStorage types.SessionStorage

	// Providers maps provider name (e.g., "google", "github") to its configuration
	Providers map[string]*OAuthProviderConfig

	// DefaultRedirectURL is the frontend URL to redirect to after successful OAuth authentication.
	// Tokens are passed as URL fragment: DefaultRedirectURL#access_token=xxx&refresh_token=xxx
	// If empty, the callback endpoint returns JSON AuthResponse instead.
	DefaultRedirectURL string

	// ErrorRedirectURL is the URL to redirect to when OAuth authentication fails.
	// Error details are passed as query params: ErrorRedirectURL?error=xxx&error_description=xxx
	// If empty, the callback endpoint returns JSON error response instead.
	ErrorRedirectURL string

	// AllowSignup allows creating new users via OAuth (default: true)
	// If false, only existing users can authenticate via OAuth
	AllowSignup bool

	// AllowAccountLinking allows linking OAuth to existing accounts with matching email (default: true)
	// If false, OAuth login fails if email already exists with password auth
	AllowAccountLinking bool

	// TrustEmailVerification trusts the OAuth provider's email verification status (default: true)
	// If true, sets EmailVerified=true when provider reports email as verified
	TrustEmailVerification bool

	// StateTTL is how long OAuth state tokens remain valid (default: 10 minutes)
	StateTTL time.Duration

	// StoreProviderTokens enables storing OAuth provider access/refresh tokens in the Account model.
	// If true, tokens are encrypted and stored for API access to the provider.
	// Default: false (tokens are not stored)
	StoreProviderTokens bool

	// UseSessionAuth determines if OAuth should create database sessions (like session module)
	// or use stateless JWT tokens.
	// - true: Creates session record in database (requires SessionStorage)
	// - false: Uses stateless JWT tokens (default)
	UseSessionAuth bool
}

// OAuthProviderConfig holds configuration for a single OAuth provider
type OAuthProviderConfig struct {
	// Type selects a protocol adapter independently of this connection's map key.
	// Empty preserves the legacy provider-name convention.
	Type string
	// MicrosoftTenantID pins Microsoft trust to an explicit tenant UUID.
	MicrosoftTenantID string
	// ClientID is the OAuth client ID from the provider
	ClientID string

	// ClientSecret is the OAuth client secret from the provider
	ClientSecret string

	// Scopes to request from the provider. Uses provider defaults if empty.
	// Google default: ["openid", "email", "profile"]
	// GitHub default: ["user:email", "read:user"]
	// Microsoft default: ["openid", "email", "profile", "User.Read"]
	// Discord default: ["identify", "email"]
	Scopes []string

	// RedirectURL overrides the callback URL for this provider.
	// If empty, auto-generated as: {APIURL}{BasePath}/oauth/{provider}/callback
	RedirectURL string

	// PKCE enables Proof Key for Code Exchange (default: true)
	// Recommended for all OAuth flows for additional security
	PKCE bool

	// Enabled allows disabling a provider without removing its configuration (default: true)
	Enabled bool
}

// two factor
type TwoFactorConfig struct {
	Issuer           string // Name shown in authenticator app
	Required         bool   // Make 2FA mandatory for all users
	BackupCodesCount int    // Number of backup codes to generate
	CodeLength       int    // Length of backup codes
}

// Validate validates the configuration
func (c *Config) Validate() error {
	for _, proxy := range c.TrustedProxies {
		if !isIPOrCIDR(proxy) {
			return ErrConfig(fmt.Sprintf("invalid trusted proxy %q: expected an IP address or CIDR block", proxy))
		}
	}
	if c.RateLimit != nil {
		for _, entry := range c.RateLimit.Allowlist {
			if !isIPOrCIDR(entry) {
				return ErrConfig(fmt.Sprintf("invalid rate limit allowlist entry %q: expected an IP address or CIDR block", entry))
			}
		}
	}
	if c.MaxConcurrentRequests == 0 {
		c.MaxConcurrentRequests = 128
	}
	if c.MaxConcurrentRequests < 1 {
		return ErrConfig("maximum concurrent requests must be positive")
	}
	if c.MaxRequestBodyBytes == 0 {
		c.MaxRequestBodyBytes = 1 << 20
	}
	if c.MaxRequestBodyBytes < 0 {
		return ErrConfig("max request body must be positive")
	}
	if c.Security.JWTIssuer == "" {
		c.Security.JWTIssuer = "goauth"
	}
	if c.Security.JWTAudience == "" {
		c.Security.JWTAudience = "goauth"
	}
	switch c.Security.AuthMode {
	case "":
		c.Security.AuthMode = types.AuthModeBoth
	case types.AuthModeCookie, types.AuthModeBearer, types.AuthModeBoth:
	default:
		return ErrConfig("unsupported authentication transport")
	}
	if c.Storage == nil {
		return ErrConfig("storage backend is required")
	}
	// Default JWT algorithm is HS256 (uses JwtSecretKey). For asymmetric
	// algorithms the secret is optional — signing uses the PEM key — but we
	// still require JwtSecretKey for cookie encoding / other HMAC use.
	if len(c.Security.JwtSecretKey) < 32 {
		return ErrConfig("jwt secret key must be at least 32 characters")
	}
	if c.Security.JWTAlgorithm.IsAsymmetric() {
		if len(c.Security.JWTPrivateKeyPEM) == 0 && c.Security.JWTPrivateKeyFile == "" {
			return ErrConfig(fmt.Sprintf("%s requires JWTPrivateKeyPEM or JWTPrivateKeyFile", c.Security.JWTAlgorithm))
		}
	}
	if len(c.Security.EncryptionKey) < 16 {
		return ErrConfig("encryption key must be at least 16 characters")
	}
	if c.Security.HashSaltLength <= 0 {
		c.Security.HashSaltLength = 10 // Default to 10
	}
	if c.Security.HashSaltLength < 4 || c.Security.HashSaltLength > 31 {
		return ErrConfig("bcrypt cost must be between 4 and 31")
	}
	activeEncryptionID := c.Security.EncryptionKeyID
	if activeEncryptionID == "" {
		activeEncryptionID = "default"
	}
	for id, key := range c.Security.DecryptionKeys {
		if id == "" || id == activeEncryptionID || len(key) < 16 {
			return ErrConfig("retained encryption keys require distinct IDs and at least 16 characters")
		}
	}
	if c.Security.Session.Name == "" {
		c.Security.Session.Name = "session"
	}
	if c.Security.Session.Path == "" {
		c.Security.Session.Path = "/"
	}
	if c.Security.Session.SameSite == 0 {
		c.Security.Session.SameSite = http.SameSiteLaxMode
	}
	c.Security.Session.HttpOnly = true
	if c.Security.Session.SameSite == http.SameSiteNoneMode && !c.Security.Session.Secure {
		return ErrConfig("SameSite=None requires secure cookies")
	}
	if err := (&http.Cookie{Name: "goauth_access_" + c.Security.Session.Name, Path: c.Security.Session.Path, Domain: c.Security.Session.Domain}).Valid(); err != nil {
		return ErrConfig("invalid credential cookie configuration")
	}
	if c.Security.Session.SessionTTL <= 0 {
		c.Security.Session.SessionTTL = 30 * 24 * time.Hour // Default to 24 hours
	}
	if c.Security.Session.RefreshTokenTTL <= 0 {
		c.Security.Session.RefreshTokenTTL = 7 * 24 * time.Hour // Default to 7 days
	}
	if c.Security.Session.AccessTokenTTL <= 0 {
		c.Security.Session.AccessTokenTTL = 15 * time.Minute
	}
	// Password policy defaults
	if c.Security.PasswordPolicy.MinLength <= 0 {
		c.Security.PasswordPolicy.MinLength = 8
	}
	if c.Security.PasswordPolicy.MaxLength <= 0 || c.Security.PasswordPolicy.MaxLength > 72 {
		c.Security.PasswordPolicy.MaxLength = 72
	}
	if c.Security.PasswordPolicy.MinLength > c.Security.PasswordPolicy.MaxLength {
		return ErrConfig("password minimum exceeds maximum")
	}
	// Lockout defaults (enabled by default for security)
	c.Security.Lockout.Enabled = !c.Security.Lockout.Disabled
	if c.Security.Lockout.MaxAttempts <= 0 {
		c.Security.Lockout.MaxAttempts = 5
	}
	if c.Security.Lockout.LockoutDuration <= 0 {
		c.Security.Lockout.LockoutDuration = 15 * time.Minute
	}
	if c.BasePath == "" {
		c.BasePath = "/auth"
	}
	if c.ModuleConfigs == nil {
		c.ModuleConfigs = make(map[string]interface{})
	}

	return nil
}

func (c *Config) GetModuleConfig(name string) interface{} {
	return c.ModuleConfigs[name]
}

// isIPOrCIDR reports whether value parses as an IP address or a CIDR block.
func isIPOrCIDR(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return true
	}
	return net.ParseIP(value) != nil
}
