package types

import (
	"net/http"
	"time"

	"github.com/bete7512/goauth/hooks"
	"github.com/bete7512/goauth/interfaces"
	"github.com/bete7512/goauth/logger"
)

type Config struct {
	// Server configuration
	Server      ServerConfig
	BasePath    string
	Domain      string
	FrontendURL string
	Swagger     SwaggerConfig

	// Authentication configuration
	AuthConfig     AuthConfig
	PasswordPolicy PasswordPolicy
	Providers      ProvidersConfig

	// Storage Configuration
	Database                      DatabaseConfig
	EnableCustomStorageRepository bool
	StorageRepositoryFactory      CustomStorageRepositoryConfig

	// Notification
	EmailSender EmailSender
	SMSSender   SMSSender

	// Rate limiting
	RateLimiter       *RateLimiterConfig
	EnableRateLimiter bool

	// Custom JWT Token functionality
	EnableAddCustomJWTClaims bool
	CustomJWTClaimsProvider  CustomJWTClaimsProvider

	// Redis configuration
	RedisConfig RedisConfig

	// Recaptcha configuration
	RecaptchaConfig *RecaptchaConfig
	EnableRecaptcha bool

	// JWT configuration
	JWTSecret string
}

// AuthConfig consolidates authentication-related settings
type AuthConfig struct {
	Cookie                        CookieConfig
	EnableBearerAuth              bool
	EnableTwoFactor               bool
	EnableMultiSession            bool
	TwoFactorMethod               string
	EnableMagicLink               bool
	EnableEmailVerification       bool
	EnableSmsVerification         bool
	EmailVerificationURL          string
	PasswordResetURL              string
	SendVerificationEmailOnSignup bool
}

type CustomStorageRepositoryConfig struct {
	Factory interfaces.RepositoryFactory
}

type CookieConfig struct {
	Name            string // Renamed from CookieName
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	Secure          bool // Renamed from CookieSecure
	HttpOnly        bool
	Domain          string // Renamed from CookieDomain
	Path            string // Renamed from CookiePath
	MaxAge          int    // Renamed from MaxCookieAge
	SameSite        http.SameSite
}

type PasswordPolicy struct {
	HashSaltLength int
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
}

type ServerConfig struct {
	Type ServerType
	Host string // Added for consistency with your SwaggerConfig
	Port int    // Added since most servers need a port
}

type DatabaseConfig struct {
	Type        DatabaseType
	URL         string
	AutoMigrate bool
}

type ProvidersConfig struct {
	Enabled   []AuthProvider
	Google    ProviderConfig
	GitHub    ProviderConfig
	Facebook  ProviderConfig
	Microsoft ProviderConfig
	Apple     ProviderConfig
	Twitter   ProviderConfig
	LinkedIn  ProviderConfig
	Discord   ProviderConfig
	Spotify   ProviderConfig
	Slack     ProviderConfig
}

type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	TenantId     *string
}

type Auth struct {
	Config           Config
	Repository       interfaces.RepositoryFactory
	HookManager      *hooks.HookManager
	TokenManager     TokenManagerInterface
	RateLimiter      *RateLimiter
	RecaptchaManager CaptchaVerifier
	Logger           logger.Log
}

type SwaggerConfig struct {
	Enable      bool
	Title       string
	Version     string
	Description string
	DocPath     string
	Host        string
}

type RedisConfig struct {
	Host     string
	Port     int
	Database int
	Password string
}

type RateLimiterConfig struct {
	Type          RateLimiterStorageType
	Routes        map[string]LimiterConfig // Changed from array to map with route as key
	DefaultConfig LimiterConfig            // Added for routes without specific config
}

type LimiterConfig struct {
	WindowSize    time.Duration
	MaxRequests   int
	BlockDuration time.Duration
}

type RecaptchaConfig struct {
	SecretKey string
	SiteKey   string
	Provider  RecaptchaProvider
	APIURL    string
	Routes    map[string]bool
}
