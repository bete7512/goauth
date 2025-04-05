package types

import (
	"net/http"
	"time"

	"github.com/bete7512/goauth/hooks"
	"github.com/bete7512/goauth/interfaces"
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

	// Database and data access
	Database                 DatabaseConfig
	StorageRepositoryFactory CustomStorageRepositoryConfig

	// Communication
	EmailSender EmailSender
	SMSSender   SMSSender

	// Security features
	RateLimiter RateLimiterConfig

	// Custom functionality
	CustomJWTClaimsProvider CustomJWTClaimsProvider

	// Redis configuration
	RedisConfig RedisConfig
}

// AuthConfig consolidates authentication-related settings
type AuthConfig struct {
	JWTSecret                     string
	Cookie                        CookieConfig
	EnableBearerAuth              bool
	EnableTwoFactor               bool
	TwoFactorMethod               string
	EnableMagicLink               bool
	EnableEmailVerification       bool
	EnableSmsVerification         bool
	EmailVerificationURL          string
	PasswordResetURL              string
	EnableAddCustomJWTClaims      bool
	EnableRateLimiter             bool
	EnableCustomStorageRepository bool
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
	Config       Config
	Repository   interfaces.RepositoryFactory
	HookManager  *hooks.HookManager
	TokenManager TokenManagerInterface
	RateLimiter  *RateLimiter
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
	Type                       RateLimiterStorageType
	Routes                     map[string]LimiterConfig // Changed from array to map with route as key
	DefaultConfig              LimiterConfig            // Added for routes without specific config
	EnableBruteForceProtection bool
	BruteForceProtection       BruteForceConfig // Added for auth endpoints specifically
}

type LimiterConfig struct {
	WindowSize    time.Duration
	MaxRequests   int
	BlockDuration time.Duration
}

// New type for brute force protection specific settings
type BruteForceConfig struct {
	MaxAttempts          int           // Max login attempts before temporary lock
	ProgressiveBlocking  bool          // Whether to increase block time with consecutive failures
	InitialBlockDuration time.Duration // Starting block duration
	MaxBlockDuration     time.Duration // Maximum block duration for progressive blocks
	TrackByIP            bool          // Track attempts by IP address
	TrackByUsername      bool          // Track attempts by username
	TrackByCombined      bool          // Track attempts by IP+username combination
}
