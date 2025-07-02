// config/config.go
package config

import (
	"github.com/alitto/pond/v2"
	"github.com/bete7512/goauth/internal/hooks"
	"github.com/bete7512/goauth/internal/logger"
	"github.com/bete7512/goauth/pkg/interfaces"
)

// Main configuration struct - keep only core settings
type Config struct {
	// Core application settings
	App        AppConfig
	AuthConfig AuthConfig
	Security   SecurityConfig

	// External services
	Database  DatabaseConfig
	Redis     RedisConfig
	Providers ProvidersConfig

	// Communications
	Email EmailConfig
	SMS   SMSConfig

	WorkerPool pond.Pool

	// Features (optional/toggleable)
	Features FeaturesConfig
}

// config/app.go
type AppConfig struct {
	BasePath    string
	Domain      string
	FrontendURL string
	Swagger     SwaggerConfig
}

type SwaggerConfig struct {
	Enable      bool
	Title       string
	Version     string
	Description string
	DocPath     string
	Host        string
}

type FeaturesConfig struct {
	EnableRateLimiter   bool
	EnableRecaptcha     bool
	EnableCustomJWT     bool
	EnableCustomStorage bool
}

type Auth struct {
	Config           Config
	Repository       interfaces.RepositoryFactory
	HookManager      hooks.HookManager
	TokenManager     interfaces.TokenManagerInterface
	RateLimiter      interfaces.RateLimiter
	RecaptchaManager interfaces.CaptchaVerifier
	CSRFManager      interfaces.CSRFManager
	EmailSender      interfaces.EmailSenderInterface
	WorkerPool       pond.Pool
	Logger           logger.Log
}
