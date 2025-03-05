package types

import (
	"time"

	"github.com/bete7512/go-auth/auth/hooks"
	"github.com/bete7512/go-auth/auth/interfaces"
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
	RouteRegister       = "register"
	RouteLogin          = "login"
	RouteLogout         = "logout"
	RouteRefreshToken   = "refresh-token"
	RouteForgotPassword = "forgot-password"
	RouteResetPassword  = "reset-password"
	RouteUpdateUser     = "update-user"
	RouteDeactivateUser = "deactivate-user"
	RouteGetUser        = "get-user"
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
	Database                DatabaseConfig // Database configuration
	Server                  ServerConfig
	BasePath                string
	AccessTokenTTL          time.Duration
	CookieSecure            bool
	CookieDomain            string
	JWTSecret               string
	RefreshTokenTTL         time.Duration
	EnableTwoFactor         bool
	PasswordPolicy          PasswordPolicy
	Providers               ProvidersConfig
	TwoFactorMethod         string
	EnableEmailVerification bool
	EnableSmsVerification   bool
	EmailVerificationURL    string
	PasswordResetURL        string
	EmailSender             EmailSender
	SMSSender               SMSSender
}

type PasswordPolicy struct {
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
	SendVerification(email string, params ...interface{}) error
	SendPasswordReset(email string, params ...interface{}) error
	SendTwoFactorCode(email string, params ...interface{}) error
}

type SMSSender interface {
	SendTwoFactorCode(phone string, params ...interface{}) error
}

type Auth struct {
	Config      Config
	Db          DatabaseConfig
	Repository  interfaces.RepositoryFactory
	HookManager *hooks.HookManager
}
