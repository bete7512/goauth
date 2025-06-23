package goauth

import (
	"errors"
	"fmt"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/bete7512/goauth/api"
	"github.com/bete7512/goauth/config"
	"github.com/bete7512/goauth/database"
	"github.com/bete7512/goauth/hooks"
	"github.com/bete7512/goauth/interfaces"
	"github.com/bete7512/goauth/logger"
	"github.com/bete7512/goauth/notifications/email"
	"github.com/bete7512/goauth/notifications/sms"
	"github.com/bete7512/goauth/ratelimiter"
	"github.com/bete7512/goauth/recaptcha"
	"github.com/bete7512/goauth/repositories"
	tokenManager "github.com/bete7512/goauth/tokens"
)

// Builder provides a flexible way to construct an AuthService.
type Builder struct {
	Config           config.Config
	repoFactory      interfaces.RepositoryFactory
	captchaVerifier  config.CaptchaVerifier
	WorkerPool       *pond.Pool
	Logger           logger.Log
	TokenManager     config.TokenManagerInterface
	RateLimiter      config.RateLimiter
	RecaptchaManager config.CaptchaVerifier
	HookManager      *hooks.HookManager
	err              error
}

// NewBuilder creates a new builder instance.
func NewBuilder() *Builder {
	return &Builder{}
}

// WithConfig sets the configuration for the AuthService.
func (b *Builder) WithConfig(conf config.Config) *Builder {
	b.Config = conf
	return b
}

// WithRepositoryFactory provides a custom repository factory.
func (b *Builder) WithRepositoryFactory(factory interfaces.RepositoryFactory) *Builder {
	b.repoFactory = factory
	return b
}

// WithCaptchaVerifier provides a custom captcha verifier.
func (b *Builder) WithCaptchaVerifier(verifier config.CaptchaVerifier) *Builder {
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
		if b.Config.Features.EnableCustomStorage {
			return nil, errors.New("EnableCustomStorage is true, but no factory was provided via WithRepositoryFactory")
		}
		dbClient, err := database.NewDBClient(b.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to create db client: %w", err)
		}
		if err := dbClient.Connect(); err != nil {
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}
		repoFactory, err := repositories.NewRepositoryFactory(b.Config.Database.Type, dbClient.GetDB())
		if err != nil {
			return nil, fmt.Errorf("failed to create repository factory: %w", err)
		}
		b.repoFactory = repoFactory
	}

	// If a custom captcha verifier isn't provided, create the default one if enabled.
	if b.captchaVerifier == nil && b.Config.Security.Recaptcha.Enabled {
		if b.Config.Security.Recaptcha.SecretKey == "" {
			return nil, errors.New("EnableRecaptcha is true, but RecaptchaConfig is not properly configured")
		}
		b.captchaVerifier = recaptcha.NewRecaptchaVerifier(b.Config.Security.Recaptcha)
	}

	// Initialize email sender if not provided
	if b.Config.Email.Sender.CustomSender == nil && b.Config.Email.SendGrid.APIKey != "" {
		b.Config.Email.Sender.CustomSender = email.NewEmailSender(b.Config)
	}

	// Initialize SMS sender if not provided
	if b.Config.SMS.CustomSender == nil && b.Config.SMS.Twilio.AccountSID != "" {
		b.Config.SMS.CustomSender = sms.NewSMSSender(b.Config.SMS)
	}
	if b.repoFactory == nil {
		return nil, errors.New("repository factory is required")
	}
	if b.Config.WorkerPool == nil {
		pool := pond.NewPool(1, pond.WithQueueSize(100))
		b.Config.WorkerPool = &pool
		b.WorkerPool = &pool
		if b.Config.WorkerPool == nil {
			return nil, errors.New("worker pool is required")
		}
	}
	if b.Config.Security.RateLimiter.Enabled {
		if b.RateLimiter == nil {
			b.RateLimiter = ratelimiter.NewRateLimiter(b.Config)
		}
	}
	if b.Config.Features.EnableRecaptcha {
		if b.RecaptchaManager == nil {
			b.RecaptchaManager = recaptcha.NewRecaptchaVerifier(b.Config.Security.Recaptcha)
		}
	}

	rateLimiter := ratelimiter.NewRateLimiter(b.Config)
	tokenManager := tokenManager.NewTokenManager(b.Config)
	authService := &AuthService{
		Auth: config.Auth{
			Config:           &b.Config,
			Repository:       b.repoFactory,
			HookManager:      hooks.NewHookManager(),
			RateLimiter:      &rateLimiter,
			RecaptchaManager: b.captchaVerifier,
			Logger:           loggerInstance,
			TokenManager:     tokenManager,
			WorkerPool:       *b.Config.WorkerPool,
		},
	}

	// Initialize AuthAPI after creating the service
	authService.AuthAPI = api.NewAuthAPI(&authService.Auth)

	// Set default TTLs if not configured
	if b.Config.AuthConfig.Tokens.EmailVerificationTTL <= 0 {
		b.Config.AuthConfig.Tokens.EmailVerificationTTL = 1 * time.Hour
	}
	if b.Config.AuthConfig.Tokens.PhoneVerificationTTL <= 0 {
		b.Config.AuthConfig.Tokens.PhoneVerificationTTL = 10 * time.Minute
	}
	if b.Config.AuthConfig.Tokens.PasswordResetTTL <= 0 {
		b.Config.AuthConfig.Tokens.PasswordResetTTL = 10 * time.Minute
	}
	if b.Config.AuthConfig.Tokens.TwoFactorTTL <= 0 {
		b.Config.AuthConfig.Tokens.TwoFactorTTL = 10 * time.Minute
	}
	if b.Config.AuthConfig.Tokens.MagicLinkTTL <= 0 {
		b.Config.AuthConfig.Tokens.MagicLinkTTL = 10 * time.Minute
	}

	if b.Config.Features.EnableCustomJWT {
		if b.Config.AuthConfig.JWT.ClaimsProvider == nil {
			return nil, errors.New("custom JWT claims provider is required when custom JWT claims are enabled")
		}

	}
	if b.Config.App.Swagger.Enable {
		if b.Config.App.Swagger.Title == "" {
			return nil, errors.New("swagger title is required when swagger is enabled")
		}
		if b.Config.App.Swagger.Version == "" {
			return nil, errors.New("swagger version is required when swagger is enabled")
		}
		if b.Config.App.Swagger.DocPath == "" || b.Config.App.Swagger.DocPath == "/" {
			return nil, errors.New("swagger doc path is required when swagger is enabled")
		}
	}

	return authService, nil
}

// validate performs comprehensive validation of the configuration
func (b *Builder) validate() error {
	// Validate server configuration
	if b.Config.Server.Type == "" {
		return errors.New("server type is required")
	}

	// Validate database configuration
	if !b.Config.Features.EnableCustomStorage {
		if b.Config.Database.URL == "" {
			return errors.New("database URL is required when not using custom storage repository")
		}
		if b.Config.Database.Type == "" {
			return errors.New("database type is required when not using custom storage repository")
		}
	} else if b.repoFactory == nil {
		return errors.New("repository factory is required when EnableCustomStorage is true")
	}

	// Validate JWT configuration
	if b.Config.AuthConfig.JWT.Secret == "" {
		return errors.New("JWT secret is required")
	}

	// Validate cookie configuration
	if b.Config.AuthConfig.Cookie.Name == "" {
		return errors.New("cookie name is required")
	}
	if b.Config.AuthConfig.JWT.AccessTokenTTL <= 0 {
		return errors.New("access token TTL must be greater than 0")
	}
	if b.Config.AuthConfig.JWT.RefreshTokenTTL <= 0 {
		return errors.New("refresh token TTL must be greater than 0")
	}
	if b.Config.AuthConfig.Cookie.Path == "" {
		return errors.New("cookie path is required")
	}
	if b.Config.AuthConfig.Cookie.MaxAge <= 0 {
		return errors.New("max cookie age must be greater than 0")
	}
	if b.Config.AuthConfig.Tokens.HashSaltLength <= 0 {
		b.Config.AuthConfig.Tokens.HashSaltLength = 10
	}
	// Validate password policy
	if b.Config.AuthConfig.PasswordPolicy.HashSaltLength <= 0 {
		b.Config.AuthConfig.PasswordPolicy.HashSaltLength = 10
	}

	if b.Config.AuthConfig.PasswordPolicy.MinLength <= 0 {
		b.Config.AuthConfig.PasswordPolicy.MinLength = 8
	}

	// Validate two-factor authentication
	if b.Config.AuthConfig.Methods.EnableTwoFactor && b.Config.AuthConfig.Methods.TwoFactorMethod == "" {
		return errors.New("two-factor method is required when two-factor authentication is enabled")
	}

	// Validate email verification
	if b.Config.AuthConfig.Methods.EmailVerification.EnableOnSignup {
		if b.Config.AuthConfig.Methods.EmailVerification.VerificationURL == "" {
			return errors.New("email verification URL is required when email verification is enabled")
		}
		if b.Config.Email.Sender.CustomSender == nil {
			b.Config.Email.Sender.CustomSender = email.NewEmailSender(b.Config)
		}
	}

	// Validate SMS verification
	if b.Config.AuthConfig.Methods.EnableSmsVerification && b.Config.SMS.CustomSender == nil {
		return errors.New("SMS sender is required when SMS verification is enabled")
	}

	// Validate rate limiter
	if b.Config.Features.EnableRateLimiter && !b.Config.Security.RateLimiter.Enabled {
		return errors.New("rate limiter configuration is required when rate limiting is enabled")
	}

	// Validate custom JWT claims
	if b.Config.Features.EnableCustomJWT && b.Config.AuthConfig.JWT.ClaimsProvider == nil {
		return errors.New("custom JWT claims provider is required when custom JWT claims are enabled")
	}

	// Validate Swagger configuration
	if b.Config.App.Swagger.Enable {
		if b.Config.App.Swagger.Title == "" {
			return errors.New("swagger title is required when swagger is enabled")
		}
		if b.Config.App.Swagger.Version == "" {
			return errors.New("swagger version is required when swagger is enabled")
		}
		if b.Config.App.Swagger.DocPath == "" || b.Config.App.Swagger.DocPath == "/" {
			return errors.New("swagger doc path is required when swagger is enabled")
		}
		if b.Config.App.Swagger.Description == "" {
			return errors.New("swagger description is required when swagger is enabled")
		}
		if b.Config.App.Swagger.Host == "" {
			return errors.New("swagger host is required when swagger is enabled")
		}
	}

	if b.Config.WorkerPool == nil {
		return errors.New("worker pool is required")
	}

	// Validate OAuth providers
	return b.validateProviders()
}

// validateProviders validates OAuth provider configurations
func (b *Builder) validateProviders() error {
	for _, provider := range b.Config.Providers.Enabled {
		var providerConfig config.ProviderConfig
		switch provider {
		case config.Google:
			providerConfig = b.Config.Providers.Google
		case config.GitHub:
			providerConfig = b.Config.Providers.GitHub
		case config.Facebook:
			providerConfig = b.Config.Providers.Facebook
		case config.Microsoft:
			providerConfig = b.Config.Providers.Microsoft
		case config.Apple:
			providerConfig = b.Config.Providers.Apple
		case config.Discord:
			providerConfig = b.Config.Providers.Discord
		case config.Twitter:
			providerConfig = b.Config.Providers.Twitter
		case config.LinkedIn:
			providerConfig = b.Config.Providers.LinkedIn
		case config.Slack:
			providerConfig = b.Config.Providers.Slack
		case config.Spotify:
			providerConfig = b.Config.Providers.Spotify
		default:
			return fmt.Errorf("unsupported OAuth provider: %s", provider)
		}

		if providerConfig.ClientID == "" {
			return fmt.Errorf("client ID is required for OAuth provider: %s", provider)
		}
		if providerConfig.ClientSecret == "" {
			return fmt.Errorf("client secret is required for OAuth provider: %s", provider)
		}
		if providerConfig.RedirectURL == "" {
			return fmt.Errorf("redirect URL is required for OAuth provider: %s", provider)
		}
	}

	return nil
}
