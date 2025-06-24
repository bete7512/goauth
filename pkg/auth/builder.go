package auth

import (
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/bete7512/goauth/internal/api"
	"github.com/bete7512/goauth/internal/database"
	"github.com/bete7512/goauth/internal/hooks"
	"github.com/bete7512/goauth/internal/logger"
	"github.com/bete7512/goauth/internal/notifications/email"
	"github.com/bete7512/goauth/internal/notifications/sms"
	"github.com/bete7512/goauth/internal/ratelimiter"
	"github.com/bete7512/goauth/internal/recaptcha"
	"github.com/bete7512/goauth/internal/repositories"
	tokenManager "github.com/bete7512/goauth/internal/tokens"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

// Builder provides a flexible way to construct an AuthService.
type Builder struct {
	config.Auth
}

/*
type Auth struct {
    Config           Config
    Repository       interfaces.RepositoryFactory
    HookManager      *hooks.HookManager
    TokenManager     interfaces.TokenManagerInterface
    RateLimiter      interfaces.RateLimiter
    RecaptchaManager interfaces.CaptchaVerifier
    WorkerPool       pond.Pool
    Logger           logger.Log
}
*/

// NewBuilder creates a new builder instance with sensible defaults.
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
	b.Repository = factory
	return b
}

// WithCaptchaVerifier provides a custom captcha verifier.
func (b *Builder) WithCaptchaVerifier(verifier interfaces.CaptchaVerifier) *Builder {
	b.RecaptchaManager = verifier
	return b
}

// WithWorkerPool provides a custom worker pool.
func (b *Builder) WithWorkerPool(pool pond.Pool) *Builder {
	b.WorkerPool = pool
	return b
}

// WithLogger provides a custom logger.
func (b *Builder) WithLogger(log logger.Log) *Builder {
	b.Logger = log
	return b
}

// WithTokenManager provides a custom token manager.
func (b *Builder) WithTokenManager(tm interfaces.TokenManagerInterface) *Builder {
	b.TokenManager = tm
	return b
}

// WithRateLimiter provides a custom rate limiter.
func (b *Builder) WithRateLimiter(rl interfaces.RateLimiter) *Builder {
	b.RateLimiter = rl
	return b
}

// WithEmailSender provides a custom email sender.
func (b *Builder) WithEmailSender(sender interfaces.EmailSenderInterface) *Builder {
	b.Config.Email.Sender.CustomSender = sender
	return b
}

// WithSMSSender provides a custom SMS sender.
func (b *Builder) WithSMSSender(sender interfaces.SMSSenderInterface) *Builder {
	b.Config.SMS.CustomSender = sender
	return b
}

// Build constructs the final AuthService.
func (b *Builder) Build() (*AuthService, error) {

	if b.RecaptchaManager == nil && b.Config.Features.EnableRecaptcha {
		b.RecaptchaManager = recaptcha.NewRecaptchaVerifier(b.Config.Security.Recaptcha)
	}
	if b.Config.Email.Sender.CustomSender == nil && b.Config.AuthConfig.Methods.EmailVerification.EnableOnSignup && b.Config.Email.Sender.Type == config.SendGrid {
		b.Config.Email.Sender.CustomSender = email.NewEmailSender(b.Config)
	}
	if b.Config.SMS.CustomSender == nil && b.Config.AuthConfig.Methods.EnableSmsVerification && b.Config.SMS.Twilio.AccountSID != "" {
		b.Config.SMS.CustomSender = sms.NewSMSSender(b.Config.SMS)
	}

	// Validate configuration first
	if err := b.validateConfig(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Set default token TTLs
	b.setDefaultTokenTTLs()

	// Initialize components in order
	if err := b.initializeLogger(); err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	if err := b.initializeWorkerPool(); err != nil {
		return nil, fmt.Errorf("failed to initialize worker pool: %w", err)
	}

	if err := b.initializeRepositoryFactory(); err != nil {
		return nil, fmt.Errorf("failed to initialize repository factory: %w", err)
	}

	if err := b.initializeCaptchaVerifier(); err != nil {
		return nil, fmt.Errorf("failed to initialize captcha verifier: %w", err)
	}

	if err := b.initializeNotificationSenders(); err != nil {
		return nil, fmt.Errorf("failed to initialize notification senders: %w", err)
	}

	if err := b.initializeRateLimiter(); err != nil {
		return nil, fmt.Errorf("failed to initialize rate limiter: %w", err)
	}

	if err := b.initializeTokenManager(); err != nil {
		return nil, fmt.Errorf("failed to initialize token manager: %w", err)
	}

	if err := b.initializeHookManager(); err != nil {
		return nil, fmt.Errorf("failed to initialize hook manager: %w", err)
	}

	// Create the auth handler
	authHandler := api.NewAuthHandler(&config.Auth{
		Config:           b.Config,
		Repository:       b.Repository,
		HookManager:      b.HookManager,
		RateLimiter:      b.RateLimiter,
		RecaptchaManager: b.RecaptchaManager,
		Logger:           b.Logger,
		TokenManager:     b.TokenManager,
		WorkerPool:       b.WorkerPool,
	})

	return &AuthService{
		AuthHandler: authHandler,
	}, nil
}

// initializeLogger sets up the logger if not provided
func (b *Builder) initializeLogger() error {
	if b.Logger != nil {
		return nil
	}

	logger.New("info", logger.LogOptions{})
	loggerInstance := logger.Get()
	if loggerInstance == nil {
		return errors.New("failed to initialize logger")
	}
	b.Logger = loggerInstance
	return nil
}

// initializeWorkerPool sets up the worker pool if not provided
func (b *Builder) initializeWorkerPool() error {
	if b.WorkerPool != nil {
		return nil
	}

	if b.Config.WorkerPool != nil {
		b.WorkerPool = b.Config.WorkerPool
		return nil
	}

	// Create default worker pool
	pool := pond.NewPool(runtime.NumGoroutine())
	b.WorkerPool = pool
	b.Config.WorkerPool = pool
	return nil
}

// initializeRepositoryFactory sets up the repository factory if not provided
func (b *Builder) initializeRepositoryFactory() error {
	if b.Repository != nil {
		return nil
	}

	if b.Config.Features.EnableCustomStorage {
		return errors.New("custom storage is enabled but no repository factory was provided")
	}

	dbClient, err := database.NewDBClient(b.Config)
	if err != nil {
		return fmt.Errorf("failed to create database client: %w", err)
	}

	if err := dbClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	repoFactory, err := repositories.NewRepositoryFactory(b.Config.Database.Type, dbClient.GetDB())
	if err != nil {
		return fmt.Errorf("failed to create repository factory: %w", err)
	}

	b.Repository = repoFactory
	return nil
}

// initializeCaptchaVerifier sets up the captcha verifier if needed
func (b *Builder) initializeCaptchaVerifier() error {
	if b.RecaptchaManager != nil {
		return nil
	}

	if !b.Config.Security.Recaptcha.Enabled && !b.Config.Features.EnableRecaptcha {
		return nil // Not needed
	}

	if b.Config.Security.Recaptcha.SecretKey == "" {
		return errors.New("recaptcha is enabled but secret key is not configured")
	}

	b.RecaptchaManager = recaptcha.NewRecaptchaVerifier(b.Config.Security.Recaptcha)
	return nil
}

// initializeNotificationSenders sets up email and SMS senders if needed
func (b *Builder) initializeNotificationSenders() error {
	// Initialize email sender
	if b.Config.Email.Sender.CustomSender == nil &&
		b.Config.AuthConfig.Methods.EmailVerification.EnableOnSignup &&
		b.Config.Email.SendGrid.APIKey != "" {
		b.Config.Email.Sender.CustomSender = email.NewEmailSender(b.Config)
	}

	// Initialize SMS sender
	if b.Config.SMS.CustomSender == nil &&
		b.Config.AuthConfig.Methods.EnableSmsVerification &&
		b.Config.SMS.Twilio.AccountSID != "" {
		b.Config.SMS.CustomSender = sms.NewSMSSender(b.Config.SMS)
	}

	return nil
}

// initializeRateLimiter sets up the rate limiter if needed
func (b *Builder) initializeRateLimiter() error {
	if b.RateLimiter != nil {
		return nil
	}

	if !b.Config.Security.RateLimiter.Enabled {
		// TODO: No need to have create a rate limiter if it's not enabled
		b.RateLimiter = nil
		return nil
	}

	rateLimiter, err := ratelimiter.New(b.Config)
	if err != nil {
		return fmt.Errorf("failed to create rate limiter: %w", err)
	}
	b.RateLimiter = rateLimiter
	return nil
}

// initializeTokenManager sets up the token manager if not provided
func (b *Builder) initializeTokenManager() error {
	if b.TokenManager != nil {
		return nil
	}

	b.TokenManager = tokenManager.NewTokenManager(b.Config)
	if b.TokenManager == nil {
		return errors.New("failed to create token manager")
	}
	return nil
}

// initializeHookManager sets up the hook manager if not provided
func (b *Builder) initializeHookManager() error {
	if b.HookManager.Hooks != nil {
		return nil
	}

	b.HookManager = hooks.NewHookManager()
	return nil
}

// setDefaultTokenTTLs sets default TTL values for tokens if not configured
func (b *Builder) setDefaultTokenTTLs() {
	if b.Config.AuthConfig.Tokens.EmailVerificationTTL <= 0 {
		b.Config.AuthConfig.Tokens.EmailVerificationTTL = 1 * time.Hour
	}
	if b.Config.AuthConfig.Tokens.PhoneVerificationTTL <= 0 {
		b.Config.AuthConfig.Tokens.PhoneVerificationTTL = 10 * time.Minute
	}
	if b.Config.AuthConfig.Tokens.TwoFactorTTL <= 0 {
		b.Config.AuthConfig.Tokens.TwoFactorTTL = 10 * time.Minute
	}
	if b.Config.AuthConfig.Tokens.MagicLinkTTL <= 0 {
		b.Config.AuthConfig.Tokens.MagicLinkTTL = 10 * time.Minute
	}
}

// validateConfig performs comprehensive validation of the configuration
func (b *Builder) validateConfig() error {
	validators := []func() error{
		b.validateDatabase,
		b.validateJWT,
		b.validateCookie,
		b.validatePasswordPolicy,
		b.validateTwoFactor,
		b.validateEmailVerification,
		b.validateSMSVerification,
		b.validateRateLimiter,
		b.validateCustomJWT,
		b.validateSwagger,
		b.validateOAuthProviders,
	}

	for _, validator := range validators {
		if err := validator(); err != nil {
			return err
		}
	}

	return nil
}

// validateDatabase validates database configuration
func (b *Builder) validateDatabase() error {
	if b.Config.Features.EnableCustomStorage {
		if b.Repository == nil {
			return errors.New("repository factory is required when custom storage is enabled")
		}
		return nil
	}

	if b.Config.Database.URL == "" {
		return errors.New("database URL is required when not using custom storage")
	}
	if b.Config.Database.Type == "" {
		return errors.New("database type is required when not using custom storage")
	}

	return nil
}

// validateJWT validates JWT configuration
func (b *Builder) validateJWT() error {
	if b.Config.AuthConfig.JWT.Secret == "" {
		return errors.New("JWT secret is required")
	}
	if b.Config.AuthConfig.JWT.AccessTokenTTL <= 0 {
		return errors.New("access token TTL must be greater than 0")
	}
	if b.Config.AuthConfig.JWT.RefreshTokenTTL <= 0 {
		return errors.New("refresh token TTL must be greater than 0")
	}
	return nil
}

// validateCookie validates cookie configuration
func (b *Builder) validateCookie() error {
	if b.Config.AuthConfig.Cookie.Name == "" {
		return errors.New("cookie name is required")
	}
	if b.Config.AuthConfig.Cookie.Path == "" {
		return errors.New("cookie path is required")
	}
	if b.Config.AuthConfig.Cookie.MaxAge <= 0 {
		return errors.New("cookie max age must be greater than 0")
	}
	return nil
}

// validatePasswordPolicy validates password policy configuration
func (b *Builder) validatePasswordPolicy() error {
	if b.Config.AuthConfig.PasswordPolicy.HashSaltLength <= 0 {
		b.Config.AuthConfig.PasswordPolicy.HashSaltLength = 10
	}
	if b.Config.AuthConfig.PasswordPolicy.MinLength <= 0 {
		b.Config.AuthConfig.PasswordPolicy.MinLength = 8
	}
	if b.Config.AuthConfig.Tokens.HashSaltLength <= 0 {
		b.Config.AuthConfig.Tokens.HashSaltLength = 10
	}
	return nil
}

// validateTwoFactor validates two-factor authentication configuration
func (b *Builder) validateTwoFactor() error {
	if b.Config.AuthConfig.Methods.EnableTwoFactor &&
		b.Config.AuthConfig.Methods.TwoFactorMethod == "" {
		return errors.New("two-factor method is required when two-factor authentication is enabled")
	}
	return nil
}

// validateEmailVerification validates email verification configuration
func (b *Builder) validateEmailVerification() error {
	if b.Config.Email.Sender.CustomSender == nil {
		if b.Config.AuthConfig.Methods.EmailVerification.EnableOnSignup {
			if b.Config.AuthConfig.Methods.EmailVerification.VerificationURL == "" {
				return errors.New("email verification URL is required when email verification is enabled")
			}
		}
		if b.Config.Email.Sender.Type == config.SendGrid {
			if b.Config.Email.SendGrid.APIKey == "" {
				return errors.New("sendgrid API key is required when email verification is enabled")
			}
		} else if b.Config.Email.Sender.Type == config.SES {
			if b.Config.Email.SES.AccessKeyID == "" || b.Config.Email.SES.SecretAccessKey == "" {
				return errors.New("ses access key id and secret access key are required when email verification is enabled")
			}
		} else {
			return errors.New("either sendgrid or ses is required when email verification is enabled and custom sender is not provided")
		}
		if b.Config.Email.Sender.CustomSender == nil {
			b.Config.Email.Sender.CustomSender = email.NewEmailSender(b.Config)
		}
	}
	return nil
}

// validateSMSVerification validates SMS verification configuration
func (b *Builder) validateSMSVerification() error {
	if b.Config.SMS.CustomSender == nil {
		if b.Config.AuthConfig.Methods.EnableSmsVerification {
			if b.Config.SMS.Twilio.AccountSID == "" || b.Config.SMS.Twilio.AuthToken == "" || b.Config.SMS.Twilio.FromNumber == "" {
				return errors.New("twilio account sid, auth token and from number are required when SMS verification is enabled")
			} else {
				return errors.New("either twilio or custom sender is required when SMS verification is enabled and custom sender is not provided")
			}
		}
		if b.Config.SMS.CustomSender == nil {
			b.Config.SMS.CustomSender = sms.NewSMSSender(b.Config.SMS)
		}
	}
	return nil
}

// validateRateLimiter validates rate limiter configuration
func (b *Builder) validateRateLimiter() error {
	if b.Config.Features.EnableRateLimiter && !b.Config.Security.RateLimiter.Enabled {

		return errors.New("rate limiter configuration is required when rate limiting is enabled")
	}
	return nil
}

// validateCustomJWT validates custom JWT configuration
func (b *Builder) validateCustomJWT() error {
	if b.Config.Features.EnableCustomJWT &&
		b.Config.AuthConfig.JWT.ClaimsProvider == nil {
		return errors.New("custom JWT claims provider is required when custom JWT is enabled")
	}
	return nil
}

// validateSwagger validates Swagger configuration
func (b *Builder) validateSwagger() error {
	if !b.Config.App.Swagger.Enable {
		return nil
	}

	required := map[string]string{
		"title":       b.Config.App.Swagger.Title,
		"version":     b.Config.App.Swagger.Version,
		"description": b.Config.App.Swagger.Description,
		"host":        b.Config.App.Swagger.Host,
	}

	for field, value := range required {
		if value == "" {
			return fmt.Errorf("swagger %s is required when swagger is enabled", field)
		}
	}

	if b.Config.App.Swagger.DocPath == "" || b.Config.App.Swagger.DocPath == "/" {
		return errors.New("swagger doc path is required and cannot be root when swagger is enabled")
	}

	return nil
}

// validateOAuthProviders validates OAuth provider configurations
func (b *Builder) validateOAuthProviders() error {
	providerConfigs := map[config.AuthProvider]*config.ProviderConfig{
		config.Google:    &b.Config.Providers.Google,
		config.GitHub:    &b.Config.Providers.GitHub,
		config.Facebook:  &b.Config.Providers.Facebook,
		config.Microsoft: &b.Config.Providers.Microsoft,
		config.Apple:     &b.Config.Providers.Apple,
		config.Discord:   &b.Config.Providers.Discord,
		config.Twitter:   &b.Config.Providers.Twitter,
		config.LinkedIn:  &b.Config.Providers.LinkedIn,
		config.Slack:     &b.Config.Providers.Slack,
		config.Spotify:   &b.Config.Providers.Spotify,
	}

	for _, provider := range b.Config.Providers.Enabled {
		providerConfig, exists := providerConfigs[provider]
		if !exists {
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
