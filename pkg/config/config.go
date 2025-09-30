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
	Cache     CacheConfig
	Providers ProvidersConfig

	// Communications
	Email EmailConfig
	SMS   SMSConfig

	WorkerPool pond.Pool

	// Features (optional/toggleable)
	Features FeaturesConfig
}

type FeatureFlags struct {
	EnableRateLimiting bool `yaml:"enable_rate_limiting" default:"true"`
	EnableCSRF         bool `yaml:"enable_csrf" default:"true"`
	Enable2FA          bool `yaml:"enable_2fa" default:"true"`
	EnableOAuth        bool `yaml:"enable_oauth" default:"true"`
}

// config/app.go
type AppConfig struct {
	BasePath                  string
	Domain                    string
	FrontendURL               string
	ResetPasswordFrontendPath string
	Swagger                   SwaggerConfig
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
	EnableCSRF          bool
}

type Auth struct {
	*Config
	Repository       interfaces.RepositoryFactory
	HookManager      hooks.HookManager
	TokenManager     interfaces.TokenManagerInterface
	RateLimiter      interfaces.RateLimiter
	RecaptchaManager interfaces.CaptchaVerifier
	CSRFManager      interfaces.CSRFManager
	Cache            interfaces.Cache
	// EmailSender      interfaces.EmailSenderInterface
	WorkerPool pond.Pool
	Logger     logger.Log
}
