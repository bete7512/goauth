package types

import (
	"net/http"
	"time"

	"github.com/bete7512/goauth/hooks"
	"github.com/bete7512/goauth/interfaces"
	"github.com/bete7512/goauth/models"
	"github.com/golang-jwt/jwt/v4"
)

type ServerType string

const (
	GinServer        ServerType = "gin"
	HttpServer       ServerType = "http"
	GorrilaMuxServer ServerType = "gorrila-mux"
	ChiServer        ServerType = "chi"
	FiberServer      ServerType = "fiber"
)
const (
	RouteRegister                = "register"
	RouteLogin                   = "login"
	RouteLogout                  = "logout"
	RouteRefreshToken            = "refresh-token"
	RouteForgotPassword          = "forgot-password"
	RouteResetPassword           = "reset-password"
	RouteUpdateProfile           = "update-profile"
	RouteDeactivateUser          = "deactivate-user"
	RouteGetMe                   = "me"
	RouteEnableTwoFactor         = "enable-two-factor"
	RouteVerifyTwoFactor         = "verify-two-factor"
	RouteDisableTwoFactor        = "disable-two-factor"
	RouteVerifyEmail             = "verify-email"
	RouteResendVerificationEmail = "resend-verification-email"
)

type DatabaseType string

const (
	PostgreSQL DatabaseType = "postgres"
	MySQL      DatabaseType = "mysql"
	MongoDB    DatabaseType = "mongodb"
	SQLite     DatabaseType = "sqlite"
)

type AuthProvider string

const (
	Google    AuthProvider = "google"
	GitHub    AuthProvider = "github"
	Facebook  AuthProvider = "facebook"
	Microsoft AuthProvider = "microsoft"
	Apple     AuthProvider = "apple"
)

type Config struct {
	Database                           DatabaseConfig // Database configuration
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

type EmailSender interface {
	SendVerification(user models.User, redirectUrl string) error
	SendPasswordReset(user models.User, redirectUrl string) error
	SendTwoFactorCode(user models.User, code string) error
	SendMagicLink(user models.User, redirectUrl string) error
}

type SMSSender interface {
	SendTwoFactorCode(user models.User, code string) error
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

type CustomJWTClaimsProvider interface {
	GetClaims(user models.User) (map[string]interface{}, error)
}

type TokenManagerInterface interface {
	GenerateAccessToken(user models.User, duration time.Duration, secretKey string) (string, error)
	HashPassword(password string) (string, error)
	ValidatePassword(hashedPassword, password string) error
	GenerateTokens(user *models.User) (accessToken string, refreshToken string, err error)
	ValidateToken(tokenString string) (jwt.MapClaims, error)
	GenerateRandomToken(length int) (string, error)
	GenerateBase64Token(length int) (string, error)
}
