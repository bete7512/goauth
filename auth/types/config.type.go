package types

import (
	"time"

	"github.com/bete7512/go-auth/auth/interfaces"
)

type ServerType string

const (
	GinServer   ServerType = "gin"
	HttpServer  ServerType = "http"
	MuxServer   ServerType = "mux"
	ChiServer   ServerType = "chi"
	FiberServer ServerType = "fiber"
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
	JWTSecret       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	EnableTwoFactor bool
	PasswordPolicy  PasswordPolicy
	CookieSecure    bool
	CookieDomain    string
	Server          ServerConfig
	Database        DatabaseConfig
	Auth            AuthConfig
	Providers       ProvidersConfig
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
	Type    DatabaseType
	URL     string
	Options map[string]interface{}
}

type AuthConfig struct {
	JWTSecret         string
	TokenExpiry       int
	EnableTwoFactor   bool
	TwoFactorMethod   string
	PasswordPolicy    PasswordPolicy
	EmailVerification bool
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

type PasswordHasher interface {
	Hash(password string) (string, error)
	Compare(hashedPassword, password string) error
}

type EmailSender interface {
	SendVerification(email, token string) error
	SendPasswordReset(email, token string) error
	SendTwoFactorCode(email, code string) error
}

type SMSSender interface {
	SendTwoFactorCode(phone, code string) error
}

type Auth struct {
	Config     Config
	Db         DatabaseConfig
	Repository interfaces.RepositoryFactory
}
