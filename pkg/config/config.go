package config

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// RouteInfo describes one HTTP route: its unique name, method, path, handler
// and the middleware it requires.
type RouteInfo struct {
	Name        string // Unique route identifier (e.g., "core.login", "admin.users.list")
	Method      string
	Path        string
	Handler     http.HandlerFunc
	Middlewares []types.MiddlewareName
	// Absolute mounts Path as given instead of under Config.BasePath. It is
	// for routes that must not live under the API's base path, such as
	// well-known URIs a standard places at the host root, or the ui module's
	// console mounted at a path of the host's choosing.
	Absolute bool
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

// Module is the full module contract. Auth.Use also accepts the smaller
// Component and adapts it to Module.
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

// ModuleDependencies is passed to every module's Init: storage, configuration,
// logger, event bus, middleware manager, security manager and the shared
// authentication completer.
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
	// Lookup returns another registered module by name. Use it for optional
	// collaborations, such as a page that is shown only when the audit
	// module is registered; declare required modules in Dependencies.
	// Modules may initialize in any order relative to a module found this
	// way, so call it when serving a request rather than relying on the
	// other module being initialized during Init. It may be nil in tests.
	Lookup func(name string) (Module, bool)
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

// Config is the root configuration passed to auth.New. Validate fills
// defaults and rejects invalid combinations.
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

// FrontendConfig locates the frontend pages that verification, password-reset
// and redirect links point to.
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

// CoreConfig configures the core module: signup requirements, verification
// and short-code attempt limits.
type CoreConfig struct {
	RequirePhoneNumber       bool
	RequireUserName          bool
	RequireEmailVerification bool
	RequirePhoneVerification bool
	UniquePhoneNumber        bool

	// MaxCodeAttempts caps wrong submissions of the short codes sent by SMS for
	// password reset and phone verification. The code is invalidated once the
	// cap is reached and a new one must be requested. Default: 5.
	MaxCodeAttempts int

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

	// Secure forces the Secure flag on the CSRF cookie. The cookie is Secure
	// whenever Security.Session.AllowInsecureCookies is false, so this only
	// matters for keeping it Secure in an otherwise insecure local setup.
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

// CaptchaModuleConfig holds configuration for the CAPTCHA verification module.
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

	// AllowUnverifiedEmailSignup creates accounts for identities whose email the
	// provider has not verified. Off by default: an unverified address may belong
	// to someone else, and creating an account for it lets a third party
	// pre-register that person's email. When enabled, keep
	// Core.RequireEmailVerification on so the account cannot be used until the
	// address is confirmed.
	AllowUnverifiedEmailSignup bool

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

// SAMLModuleConfig configures the SAML 2.0 service-provider module. GoAuth is
// the service provider (SP); each entry in Providers is an identity provider
// (IdP) connection such as a Keycloak realm.
//
// Linked SAML identities are stored in the accounts table owned by the OAuth
// module, so the SAML module depends on the OAuth module being registered.
type SAMLModuleConfig struct {
	// CustomCoreStorage is optional. If nil, uses deps.Storage.Core() during Init.
	CustomCoreStorage types.CoreStorage
	// CustomAccountStorage is optional. If nil, uses deps.Storage.OAuth() during Init.
	CustomAccountStorage types.OAuthStorage
	// CustomSessionStorage is optional. For session-based auth; if nil uses deps.Storage.Session() during Init.
	CustomSessionStorage types.SessionStorage

	// SPCertificate is the PEM-encoded X.509 certificate GoAuth advertises in its
	// SP metadata. It is required to sign AuthnRequests and to receive encrypted
	// assertions, which Keycloak does by default ("Client signature required").
	SPCertificate string
	// SPPrivateKey is the PEM-encoded private key (PKCS#1, PKCS#8 or EC) matching SPCertificate.
	SPPrivateKey string

	// Providers maps a connection name (e.g. "keycloak", "okta") to its IdP configuration.
	// The name appears in the login, ACS and metadata URLs.
	Providers map[string]*SAMLProviderConfig

	// DefaultRedirectURL is the frontend URL to redirect to after a successful login.
	// Tokens are passed in the URL fragment, or only as cookies in cookie auth mode.
	// If empty, the ACS endpoint returns a JSON AuthResponse instead.
	DefaultRedirectURL string

	// ErrorRedirectURL is the URL to redirect to when a SAML login fails.
	// Error details are passed as query params: ErrorRedirectURL?error=xxx&error_description=xxx
	// If empty, the ACS endpoint returns a JSON error response instead.
	ErrorRedirectURL string

	// AllowSignup creates a user for an unknown SAML subject (default: true).
	AllowSignup bool

	// AllowAccountLinking links a SAML subject to an existing user with the same
	// email address (default: false). Requires TrustEmail.
	AllowAccountLinking bool

	// TrustEmail treats the email released by the IdP as verified (default: true).
	// Enterprise IdPs vouch for the addresses they release; disable when the IdP
	// lets users set an unverified address.
	TrustEmail bool

	// RequestTTL is how long an outstanding AuthnRequest may wait for its response (default: 10 minutes).
	RequestTTL time.Duration

	// UseSessionAuth creates a database session instead of stateless JWT tokens.
	UseSessionAuth bool

	// MetadataHTTPClient fetches IdP metadata from MetadataURL during Initialize.
	// Defaults to a client with a 15 second timeout.
	MetadataHTTPClient *http.Client
}

// SAMLProviderConfig describes one identity provider connection.
type SAMLProviderConfig struct {
	// MetadataURL is the IdP metadata document, fetched once during Initialize.
	// Keycloak: {server}/realms/{realm}/protocol/saml/descriptor
	MetadataURL string
	// MetadataXML is the IdP metadata document inline. Either MetadataURL or MetadataXML is required.
	MetadataXML string

	// EntityID overrides the SP entity ID for this connection.
	// Default: {APIURL}{BasePath}/saml/{provider}/metadata
	EntityID string

	// NameIDFormat requested from the IdP: "persistent" (default), "emailAddress",
	// "unspecified" or "transient". A transient subject cannot be linked to a
	// user, so it is accepted only for users that already exist by email.
	NameIDFormat string

	// SignRequests signs AuthnRequests with SPPrivateKey (RSA-SHA256). Required
	// when the IdP has "Client signature required" enabled, which is Keycloak's default.
	SignRequests bool

	// AllowIDPInitiated accepts unsolicited responses that start at the IdP
	// (e.g. a Keycloak application tile). Such logins have no browser binding,
	// so leave it off unless the IdP needs it.
	AllowIDPInitiated bool

	// Attributes maps assertion attribute names onto user fields. Each entry
	// is tried before the built-in fallbacks (plain names, LDAP OIDs and
	// WS-Fed claim URIs).
	Attributes SAMLAttributeMapping

	// Disabled keeps the connection configured but not served.
	Disabled bool
}

// SAMLAttributeMapping names the assertion attributes that carry user fields.
type SAMLAttributeMapping struct {
	Email     string
	Name      string
	FirstName string
	LastName  string
	Username  string
	Groups    string
}

// IDPModuleConfig configures the identity provider (idp) module, which makes
// the host an OpenID Connect provider: other applications ("clients") sign
// users in with the host's accounts and receive an ID token that says who
// the user is.
//
// GoAuth has no login page of its own. The authorization endpoint hands the
// browser to ConsentURL, a page of the host's frontend, which signs the user
// in the usual way and reports the user's decision.
type IDPModuleConfig struct {
	// Issuer is the issuer identifier: the "iss" of every ID token and the
	// address of the discovery document, which is served at
	// Issuer + "/.well-known/openid-configuration".
	// Default: APIURL + BasePath + "/oidc". When set, it must be that
	// address as clients reach it, for example behind a reverse proxy. It
	// must use https unless the host is loopback or
	// Security.Session.AllowInsecureCookies is set.
	Issuer string

	// SigningKey signs ID tokens. Required. It must be a key of its own:
	// Initialize fails when it is the key that signs GoAuth's access tokens.
	SigningKey IDPSigningKey

	// ConsentURL is the frontend page where the user signs in and approves
	// the request. The browser is sent there with ?request_id=...; the page
	// reads the request from GET /oidc/consent/{id} and posts the decision.
	// Default: FrontendConfig.URL + "/oidc/consent". Required otherwise.
	ConsentURL string

	// ErrorURL is the frontend page shown when a request cannot be returned
	// to the client (unknown client, redirect URI mismatch). It receives
	// ?error=...&error_description=.... If empty the endpoint answers JSON.
	ErrorURL string

	// Clients are client applications created or updated at Initialize. A
	// client declared here cannot be changed through the admin API, and is
	// disabled when it is removed from this list.
	Clients []IDPClientConfig

	// AdminAPI serves the /admin/oidc/clients endpoints, where administrators
	// register clients at runtime. It needs the admin module. Without it,
	// Clients is the only way to register a client.
	AdminAPI bool

	// IDTokenTTL is the ID token lifetime. Default: 1 hour.
	IDTokenTTL time.Duration
	// AccessTokenTTL is the lifetime of the access token that reads the
	// UserInfo endpoint. Default: 1 hour.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is how long an unused refresh token stays valid; each
	// rotation starts a new period. Default: 30 days.
	RefreshTokenTTL time.Duration
	// RefreshTokenReuseLeeway is how long after a rotation the replaced
	// refresh token is answered with a plain error instead of being treated
	// as stolen, which absorbs retries and concurrent refreshes. Outside it
	// a replay ends the grant. Default: 10 seconds; negative disables it.
	RefreshTokenReuseLeeway time.Duration
	// AuthorizationCodeTTL is the authorization code lifetime. Default: 60 seconds.
	AuthorizationCodeTTL time.Duration
	// AuthorizationRequestTTL is how long a request waits for the user's
	// decision. Default: 10 minutes.
	AuthorizationRequestTTL time.Duration
	// CleanupInterval is how often expired requests, codes and tokens are
	// deleted. They live in the token store every module shares, so the
	// cleanup removes the expired records of the other modules too
	// (verification links, password resets, pending sign-ins), none of
	// which can be used any more. Default: 1 hour; negative disables it.
	CleanupInterval time.Duration

	// Claims adds claims of the host's own, such as roles or groups, to ID
	// tokens and UserInfo responses. Optional.
	Claims IDPClaimsFunc
}

// IDPSigningKey is the key that signs ID tokens. It must be an RSA key of at
// least 2048 bits: RS256 is the one algorithm every OpenID Connect client
// supports.
type IDPSigningKey struct {
	// PrivateKeyPEM is the PEM-encoded private key. Takes precedence over PrivateKeyFile.
	PrivateKeyPEM []byte
	// PrivateKeyFile is a path to the PEM-encoded private key.
	PrivateKeyFile string
	// KeyID is the "kid". Empty derives it from the public key.
	KeyID string
	// RetiredKeys are public keys of earlier signing keys, kept in the key
	// set until NotAfter so ID tokens they signed still verify.
	RetiredKeys []types.JWTVerificationKey
}

// IDPClientConfig declares a client application in configuration.
type IDPClientConfig struct {
	// ClientID is the public identifier the application sends.
	ClientID string
	// Secret is the client secret, at least 32 characters. Only its digest
	// is stored. Leave it empty for a Public client.
	Secret string
	// Name is shown to the user on the consent page.
	Name string
	// RedirectURIs are the exact addresses the user may be sent back to.
	RedirectURIs []string
	// Scopes limits what the client may request.
	// Default: openid, profile, email.
	Scopes []string
	// Public marks an application that cannot keep a secret, such as a
	// single-page or mobile application. It must use PKCE.
	Public bool
	// AllowWithoutPKCE accepts authorization requests without a PKCE
	// challenge, for older applications that cannot send one. It is ignored
	// for a Public client.
	AllowWithoutPKCE bool
	// SkipConsent marks an application the host operates itself: the user
	// is signed in without being asked to approve it.
	SkipConsent bool
	LogoURI     string
	ClientURI   string
	Disabled    bool
}

// IDPClaimsRequest describes the token an IDPClaimsFunc is asked about.
type IDPClaimsRequest struct {
	User     *models.User
	ClientID string
	// Scopes are the scopes the user approved for the client.
	Scopes []string
}

// IDPClaimsFunc returns claims to add to an ID token and to the UserInfo
// response. It cannot replace the claims the module sets itself. An error
// fails the token request.
type IDPClaimsFunc func(ctx context.Context, request IDPClaimsRequest) (map[string]interface{}, error)

// TwoFactorConfig configures the two-factor (TOTP) module.
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
	// Cookies are Secure unless the host explicitly opts out for local HTTP.
	c.Security.Session.Secure = !c.Security.Session.AllowInsecureCookies
	if c.Security.Session.SameSite == http.SameSiteNoneMode && c.Security.Session.AllowInsecureCookies {
		return ErrConfig("SameSite=None requires secure cookies; remove Security.Session.AllowInsecureCookies")
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

// GetModuleConfig returns the opaque configuration stored under name in
// ModuleConfigs, or nil.
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
