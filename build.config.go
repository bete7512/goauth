package goauth

import (
	"errors"
	"fmt"

	"github.com/bete7512/goauth/database"
	"github.com/bete7512/goauth/hooks"
	"github.com/bete7512/goauth/interfaces"
	"github.com/bete7512/goauth/logger"
	"github.com/bete7512/goauth/ratelimiter"
	"github.com/bete7512/goauth/recaptcha"
	"github.com/bete7512/goauth/repositories"
	"github.com/bete7512/goauth/types"
)

// Builder provides a flexible way to construct an AuthService.
type Builder struct {
	config          types.Config
	repoFactory     interfaces.RepositoryFactory
	captchaVerifier types.CaptchaVerifier
	err             error
}

// NewBuilder creates a new builder instance.
func NewBuilder() *Builder {
	return &Builder{}
}

// WithConfig sets the configuration for the AuthService.
func (b *Builder) WithConfig(conf types.Config) *Builder {
	b.config = conf
	return b
}

// WithRepositoryFactory provides a custom repository factory.
func (b *Builder) WithRepositoryFactory(factory interfaces.RepositoryFactory) *Builder {
	b.repoFactory = factory
	return b
}

// WithCaptchaVerifier provides a custom captcha verifier.
func (b *Builder) WithCaptchaVerifier(verifier types.CaptchaVerifier) *Builder {
	b.captchaVerifier = verifier
	return b
}

// Build constructs the final AuthService.
func (b *Builder) Build() (*AuthService, error) {
	if b.err != nil {
		return nil, fmt.Errorf("builder has previous error: %w", b.err)
	}

	// Validate configuration
	if err := b.validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Initialize Logger
	logger.New("info", logger.LogOptions{}) // Simplified for example
	loggerInstance := logger.Get()
	if loggerInstance == nil {
		return nil, errors.New("logger failed to initialize")
	}

	// If a custom repository factory isn't provided, create the default one.
	if b.repoFactory == nil {
		if b.config.EnableCustomStorageRepository {
			return nil, errors.New("EnableCustomStorageRepository is true, but no factory was provided via WithRepositoryFactory")
		}
		dbClient, err := database.NewDBClient(b.config.Database)
		if err != nil {
			return nil, fmt.Errorf("failed to create db client: %w", err)
		}
		if err := dbClient.Connect(); err != nil {
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}
		repoFactory, err := repositories.NewRepositoryFactory(b.config.Database.Type, dbClient.GetDB())
		if err != nil {
			return nil, fmt.Errorf("failed to create repository factory: %w", err)
		}
		b.repoFactory = repoFactory
	}

	// If a custom captcha verifier isn't provided, create the default one if enabled.
	if b.captchaVerifier == nil && b.config.EnableRecaptcha {
		if b.config.RecaptchaConfig == nil {
			return nil, errors.New("EnableRecaptcha is true, but RecaptchaConfig is nil")
		}
		b.captchaVerifier = recaptcha.NewRecaptchaVerifier(*b.config.RecaptchaConfig)
	}

	authService := &AuthService{
		Config:           b.config,
		Repository:       b.repoFactory,
		HookManager:      hooks.NewHookManager(),
		RateLimiter:      ratelimiter.NewRateLimiter(b.config),
		RecaptchaManager: b.captchaVerifier,
		Logger:           loggerInstance,
	}

	return authService, nil
}

// validate performs comprehensive validation of the configuration
func (b *Builder) validate() error {
	// Validate server configuration
	if b.config.Server.Type == "" {
		return errors.New("server type is required")
	}

	// Validate database configuration
	if !b.config.EnableCustomStorageRepository {
		if b.config.Database.URL == "" {
			return errors.New("database URL is required when not using custom storage repository")
		}
		if b.config.Database.Type == "" {
			return errors.New("database type is required when not using custom storage repository")
		}
	} else if b.repoFactory == nil {
		return errors.New("repository factory is required when EnableCustomStorageRepository is true")
	}

	// Validate JWT configuration
	if b.config.JWTSecret == "" {
		return errors.New("JWT secret is required")
	}

	// Validate cookie configuration
	if b.config.AuthConfig.Cookie.Name == "" {
		return errors.New("cookie name is required")
	}
	if b.config.AuthConfig.Cookie.AccessTokenTTL <= 0 {
		return errors.New("access token TTL must be greater than 0")
	}
	if b.config.AuthConfig.Cookie.RefreshTokenTTL <= 0 {
		return errors.New("refresh token TTL must be greater than 0")
	}
	if b.config.AuthConfig.Cookie.Path == "" {
		return errors.New("cookie path is required")
	}
	if b.config.AuthConfig.Cookie.MaxAge <= 0 {
		return errors.New("max cookie age must be greater than 0")
	}

	// Validate password policy
	if b.config.PasswordPolicy.HashSaltLength <= 0 {
		return errors.New("hash salt length must be greater than 0")
	}
	if b.config.PasswordPolicy.MinLength <= 0 {
		return errors.New("password minimum length must be greater than 0")
	}

	// Validate two-factor authentication
	if b.config.AuthConfig.EnableTwoFactor && b.config.AuthConfig.TwoFactorMethod == "" {
		return errors.New("two-factor method is required when two-factor authentication is enabled")
	}

	// Validate email verification
	if b.config.AuthConfig.EnableEmailVerification {
		if b.config.AuthConfig.EmailVerificationURL == "" {
			return errors.New("email verification URL is required when email verification is enabled")
		}
		if b.config.EmailSender == nil {
			return errors.New("email sender is required when email verification is enabled")
		}
	}

	// Validate SMS verification
	if b.config.AuthConfig.EnableSmsVerification && b.config.SMSSender == nil {
		return errors.New("SMS sender is required when SMS verification is enabled")
	}

	// Validate rate limiter
	if b.config.EnableRateLimiter && b.config.RateLimiter == nil {
		return errors.New("rate limiter configuration is required when rate limiting is enabled")
	}

	// Validate custom JWT claims
	if b.config.EnableAddCustomJWTClaims && b.config.CustomJWTClaimsProvider == nil {
		return errors.New("custom JWT claims provider is required when custom JWT claims are enabled")
	}

	// Validate Swagger configuration
	if b.config.Swagger.Enable {
		if b.config.Swagger.Title == "" {
			return errors.New("swagger title is required when swagger is enabled")
		}
		if b.config.Swagger.Version == "" {
			return errors.New("swagger version is required when swagger is enabled")
		}
		if b.config.Swagger.DocPath == "" {
			return errors.New("swagger doc path is required when swagger is enabled")
		}
		if b.config.Swagger.Description == "" {
			return errors.New("swagger description is required when swagger is enabled")
		}
		if b.config.Swagger.Host == "" {
			return errors.New("swagger host is required when swagger is enabled")
		}
	}

	// Validate OAuth providers
	return b.validateProviders()
}

// validateProviders validates OAuth provider configurations
func (b *Builder) validateProviders() error {
	for _, provider := range b.config.Providers.Enabled {
		var config types.ProviderConfig
		switch provider {
		case types.Google:
			config = b.config.Providers.Google
		case types.GitHub:
			config = b.config.Providers.GitHub
		case types.Facebook:
			config = b.config.Providers.Facebook
		case types.Microsoft:
			config = b.config.Providers.Microsoft
		case types.Apple:
			config = b.config.Providers.Apple
		case types.Discord:
			config = b.config.Providers.Discord
		case types.Twitter:
			config = b.config.Providers.Twitter
		case types.LinkedIn:
			config = b.config.Providers.LinkedIn
		case types.Slack:
			config = b.config.Providers.Slack
		case types.Spotify:
			config = b.config.Providers.Spotify
		default:
			return fmt.Errorf("unsupported OAuth provider: %s", provider)
		}

		if config.ClientID == "" {
			return fmt.Errorf("client ID is required for OAuth provider: %s", provider)
		}
		if config.ClientSecret == "" {
			return fmt.Errorf("client secret is required for OAuth provider: %s", provider)
		}
		if config.RedirectURL == "" {
			return fmt.Errorf("redirect URL is required for OAuth provider: %s", provider)
		}
	}

	return nil
}
