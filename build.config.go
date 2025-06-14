package goauth

import (
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/types"
)

type AuthBuilder struct {
	config types.Config
}

func DefaultConfig() types.Config {
	return types.Config{
		Database: types.DatabaseConfig{
			Type: types.PostgreSQL,
		},
		Server: types.ServerConfig{
			Type: types.GinServer,
		},
		AuthConfig: types.AuthConfig{
			Cookie: types.CookieConfig{
				MaxAge:          int((7 * 24 * time.Hour).Seconds()),
				Path:            "/",
				HttpOnly:        true,
				Domain:          "",
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 7 * 24 * time.Hour,
				Secure:          false,
			},
			EnableTwoFactor:         false,
			EnableEmailVerification: false,
			EnableSmsVerification:   false,
			EnableBearerAuth:        false,
		},
		PasswordPolicy: types.PasswordPolicy{
			HashSaltLength: 14,
			MinLength:      4,
			RequireUpper:   false,
			RequireLower:   false,
			RequireNumber:  false,
			RequireSpecial: false,
		},
		Swagger: types.SwaggerConfig{
			Enable: false,
		},
	}
}

func NewBuilder() *AuthBuilder {
	return &AuthBuilder{
		config: DefaultConfig(),
	}
}

func (b *AuthBuilder) WithConfig(config types.Config) *AuthBuilder {
	b.config = config
	return b
}

func (b *AuthBuilder) WithServer(serverType types.ServerType, basePath string) *AuthBuilder {
	b.config.Server.Type = serverType
	b.config.BasePath = basePath
	return b
}

func (b *AuthBuilder) WithEmailVerification(enabled bool, url string) *AuthBuilder {
	b.config.AuthConfig.EnableEmailVerification = enabled
	b.config.AuthConfig.EmailVerificationURL = url
	return b
}

func (b *AuthBuilder) WithPasswordReset(url string) *AuthBuilder {
	b.config.AuthConfig.PasswordResetURL = url
	return b
}

func (b *AuthBuilder) WithEmailSender(sender types.EmailSender) *AuthBuilder {
	b.config.EmailSender = sender
	return b
}

func (b *AuthBuilder) WithSMSSender(sender types.SMSSender) *AuthBuilder {
	b.config.SMSSender = sender
	return b
}

func (b *AuthBuilder) WithDatabase(config types.DatabaseConfig) *AuthBuilder {
	b.config.Database = config
	return b
}

func (b *AuthBuilder) WithJWT(secret string, accessTTL, refreshTTL time.Duration) *AuthBuilder {
	b.config.JWTSecret = secret
	b.config.AuthConfig.Cookie.AccessTokenTTL = accessTTL
	b.config.AuthConfig.Cookie.RefreshTokenTTL = refreshTTL
	return b
}

func (b *AuthBuilder) WithPasswordPolicy(policy types.PasswordPolicy) *AuthBuilder {
	b.config.PasswordPolicy = policy
	return b
}

func (b *AuthBuilder) WithTwoFactor(enabled bool, method string) *AuthBuilder {
	b.config.AuthConfig.EnableTwoFactor = enabled
	b.config.AuthConfig.TwoFactorMethod = method
	return b
}

func (b *AuthBuilder) WithProvider(provider types.AuthProvider, config types.ProviderConfig) *AuthBuilder {
	if b.config.Providers.Enabled == nil {
		b.config.Providers.Enabled = make([]types.AuthProvider, 0, 1)
	}
	b.config.Providers.Enabled = append(b.config.Providers.Enabled, provider)
	switch provider {
	case types.Google:
		b.config.Providers.Google = config
	case types.GitHub:
		b.config.Providers.GitHub = config
	case types.Facebook:
		b.config.Providers.Facebook = config
	case types.Microsoft:
		b.config.Providers.Microsoft = config
	case types.Apple:
		b.config.Providers.Apple = config
	}
	return b
}

func (b *AuthBuilder) WithCookie(secure bool, domain string) *AuthBuilder {
	b.config.AuthConfig.Cookie.Secure = secure
	b.config.AuthConfig.Cookie.Domain = domain
	return b
}

func (b *AuthBuilder) Build() (*types.Auth, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	return &types.Auth{Config: b.config}, nil
}

func (b *AuthBuilder) validate() error {
	if b.config.Server.Type == "" {
		return errors.New("server type is required")
	}
	if b.config.EnableCustomStorageRepository && b.config.StorageRepositoryFactory.Factory == nil {
		return errors.New("repository factory is required")
	}
	if !b.config.EnableCustomStorageRepository {
		if b.config.Database.URL == "" || b.config.Database.Type == "" {
			return errors.New("database configuration is required")
		}
	}
	if b.config.EnableRateLimiter {
		if b.config.RateLimiter == nil {
			return errors.New("rate limiter configuration is required")
		}
	}
	if b.config.EnableAddCustomJWTClaims {
		if b.config.CustomJWTClaimsProvider == nil {
			return errors.New("custom JWT claims provider is required")
		}
	}
	if b.config.EnableRecaptcha {
		if b.config.RecaptchaConfig == nil {
			return errors.New("recaptcha configuration is required")
		}
	}
	if b.config.JWTSecret == "" {
		return errors.New("JWT secret is required")
	}
	if b.config.AuthConfig.EnableTwoFactor && b.config.AuthConfig.TwoFactorMethod == "" {
		return errors.New("2FA method is required when 2FA is enabled")
	}
	if b.config.AuthConfig.EnableEmailVerification && b.config.AuthConfig.EmailVerificationURL == "" {
		return errors.New("email verification URL is required when email verification is enabled")
	}
	if b.config.AuthConfig.EnableSmsVerification && b.config.SMSSender == nil {
		return errors.New("SMS sender is required when SMS verification is enabled")
	}
	if b.config.EmailSender == nil && b.config.AuthConfig.EnableEmailVerification {
		return errors.New("email sender is required")
	}
	if b.config.AuthConfig.Cookie.MaxAge <= 0 {
		return errors.New("max cookie age must be greater than 0")
	}

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
	if b.config.PasswordPolicy.HashSaltLength <= 0 {
		return errors.New("hash salt length must be greater than 0")
	}
	if b.config.Swagger.Enable && (b.config.Swagger.Title == "" || b.config.Swagger.Version == "" || b.config.Swagger.DocPath == "" || b.config.Swagger.Description == "" || b.config.Swagger.Host == "") {
		return errors.New("swagger title and version are required when swagger is enabled")
	}

	if b.config.EnableAddCustomJWTClaims && b.config.CustomJWTClaimsProvider == nil {
		return errors.New("custom JWT claims provider is required when custom JWT claims are enabled")
	}

	return b.validateProviders()
}

func (b *AuthBuilder) validateProviders() error {
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
			return fmt.Errorf("unsupported provider: %s", provider)
		}

		if config.ClientID == "" || config.ClientSecret == "" {
			return fmt.Errorf("incomplete configuration for provider: %s", provider)
		}
	}
	return nil
}
