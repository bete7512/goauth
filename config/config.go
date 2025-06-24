// config/config.go
package config

import (
	"github.com/alitto/pond/v2"
	"github.com/bete7512/goauth/hooks"
	"github.com/bete7512/goauth/interfaces"
	"github.com/bete7512/goauth/logger"
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

	WorkerPool *pond.Pool

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

type Auth struct {
	Config           *Config
	Repository       interfaces.RepositoryFactory
	HookManager      *hooks.HookManager
	TokenManager     TokenManagerInterface
	RateLimiter      *RateLimiter
	RecaptchaManager CaptchaVerifier
	WorkerPool       pond.Pool
	Logger           logger.Log
}
