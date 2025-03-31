package types

import (
	"net/http"
	"time"

	"github.com/bete7512/goauth/hooks"
	"github.com/bete7512/goauth/interfaces"
)

type Config struct {
	Database                           DatabaseConfig
	DataAccessConfig                   DataAccessConfig
	Server                             ServerConfig
	BasePath                           string
	FrontendURL                        string
	Domain                             string
	JWTSecret                          string
	Cookie                             CookieConfig
	BearerAuthEnabled                  bool
	EnableTwoFactor                    bool
	EnableMagicLink                    bool
	PasswordPolicy                     PasswordPolicy
	Providers                          ProvidersConfig
	TwoFactorMethod                    string
	EnableEmailVerification            bool
	EnableAddCustomJWTClaims           bool
	CustomJWTClaimsProvider            CustomJWTClaimsProvider
	SendVerificationEmailOnAfterSignup bool
	EnableSmsVerification              bool
	EmailVerificationURL               string
	PasswordResetURL                   string
	EmailSender                        EmailSender
	SMSSender                          SMSSender
	Swagger                            SwaggerConfig
}

type DataAccessConfig struct {
	EnableDataAccess bool
	Factory          interfaces.RepositoryFactory
	DatabaseConfig   DatabaseConfig
}
type CookieConfig struct {
	CookieName      string
	AccessTokenTTL  time.Duration
	CookieSecure    bool
	HttpOnly        bool
	CookieDomain    string
	RefreshTokenTTL time.Duration
	CookiePath      string
	MaxCookieAge    int
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
}

type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}
type Auth struct {
	Config       Config
	Db           DatabaseConfig
	Repository   interfaces.RepositoryFactory
	HookManager  *hooks.HookManager
	TokenManager TokenManagerInterface
}

type SwaggerConfig struct {
	Title       string
	Version     string
	Description string
	Enable      bool
	DocPath     string
	Host        string
}
