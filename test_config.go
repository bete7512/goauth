package goauth

import (
	"time"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/types"
)

// --- Custom JWT Claims Provider for tests ---
type TestCustomJWTClaimsProvider struct{}

func (p *TestCustomJWTClaimsProvider) GetClaims(user models.User) (map[string]interface{}, error) {
	return map[string]interface{}{"custom_field": "custom_value"}, nil
}

// TestConfigurations provides various test configurations for different scenarios
type TestConfigurations struct{}

// MinimalConfig returns a minimal valid configuration for basic tests
func (tc *TestConfigurations) MinimalConfig() types.Config {
	return types.Config{
		Server: types.ServerConfig{
			Type: "http",
			Port: 8080,
		},
		Database: types.DatabaseConfig{
			Type: "sqlite",
			URL:  "file::memory:?cache=shared",
		},
		JWTSecret: "test-secret-key-32-chars-long",
		AuthConfig: types.AuthConfig{
			Cookie: types.CookieConfig{
				Name:            "auth_token",
				AccessTokenTTL:  3600,
				RefreshTokenTTL: 86400,
				Path:            "/",
				MaxAge:          86400,
			},
			EnableTwoFactor:         false,
			EnableEmailVerificationOnSignup: false,
		},
		PasswordPolicy: types.PasswordPolicy{
			HashSaltLength: 16,
			MinLength:      8,
		},
		EnableRateLimiter:             false,
		EnableRecaptcha:               false,
		EnableCustomStorageRepository: false,
		BasePath:                      "/api/v1",
	}
}

// FullFeatureConfig returns a configuration with all features enabled
func (tc *TestConfigurations) FullFeatureConfig() types.Config {
	config := tc.MinimalConfig()

	// Enable all features
	config.AuthConfig.EnableTwoFactor = true
	config.AuthConfig.TwoFactorMethod = "totp"
	config.AuthConfig.EnableEmailVerificationOnSignup = true
	config.AuthConfig.EmailVerificationURL = "http://localhost:8080/verify-email"
	config.AuthConfig.EnableSmsVerification = true

	// Enable rate limiting
	config.EnableRateLimiter = true
	config.RateLimiter = &types.RateLimiterConfig{
		Routes: map[string]types.LimiterConfig{
			types.RouteRegister: {
				WindowSize:    30 * time.Second,
				MaxRequests:   10,
				BlockDuration: 1 * time.Minute,
			},
		},
	}

	// Enable reCAPTCHA
	config.EnableRecaptcha = true
	config.RecaptchaConfig = &types.RecaptchaConfig{
		SecretKey: "test-secret-key",
		SiteKey:   "test-site-key",
	}

	// Enable custom JWT claims
	config.EnableAddCustomJWTClaims = true
	config.CustomJWTClaimsProvider = &TestCustomJWTClaimsProvider{}

	// Enable Swagger
	config.Swagger.Enable = true
	config.Swagger.Title = "Test API"
	config.Swagger.Version = "1.0.0"
	config.Swagger.DocPath = "/docs"
	config.Swagger.Description = "Test API Description"
	config.Swagger.Host = "localhost:8080"

	// Enable OAuth providers
	config.Providers.Enabled = []types.AuthProvider{types.Google, types.GitHub, types.Facebook, types.Microsoft, types.Apple, types.Discord}
	config.Providers.Google = types.ProviderConfig{
		ClientID:     "google-client-id",
		ClientSecret: "google-secret",
		RedirectURL:  "http://localhost:8080/oauth/google/callback",
	}
	config.Providers.GitHub = types.ProviderConfig{
		ClientID:     "github-client-id",
		ClientSecret: "github-secret",
		RedirectURL:  "http://localhost:8080/oauth/github/callback",
	}
	config.Providers.Facebook = types.ProviderConfig{
		ClientID:     "facebook-client-id",
		ClientSecret: "facebook-secret",
		RedirectURL:  "http://localhost:8080/oauth/facebook/callback",
	}
	config.Providers.Microsoft = types.ProviderConfig{
		ClientID:     "microsoft-client-id",
		ClientSecret: "microsoft-secret",
		RedirectURL:  "http://localhost:8080/oauth/microsoft/callback",
	}
	config.Providers.Apple = types.ProviderConfig{
		ClientID:     "apple-client-id",
		ClientSecret: "apple-secret",
		RedirectURL:  "http://localhost:8080/oauth/apple/callback",
	}
	config.Providers.Discord = types.ProviderConfig{
		ClientID:     "discord-client-id",
		ClientSecret: "discord-secret",
		RedirectURL:  "http://localhost:8080/oauth/discord/callback",
	}

	return config
}

// OAuthOnlyConfig returns a configuration with only OAuth features enabled
func (tc *TestConfigurations) OAuthOnlyConfig() types.Config {
	config := tc.MinimalConfig()

	// Enable OAuth providers
	config.Providers.Enabled = []types.AuthProvider{types.Google, types.GitHub, types.Facebook}
	config.Providers.Google = types.ProviderConfig{
		ClientID:     "google-client-id",
		ClientSecret: "google-secret",
		RedirectURL:  "http://localhost:8080/oauth/google/callback",
	}
	config.Providers.GitHub = types.ProviderConfig{
		ClientID:     "github-client-id",
		ClientSecret: "github-secret",
		RedirectURL:  "http://localhost:8080/oauth/github/callback",
	}
	config.Providers.Facebook = types.ProviderConfig{
		ClientID:     "facebook-client-id",
		ClientSecret: "facebook-secret",
		RedirectURL:  "http://localhost:8080/oauth/facebook/callback",
	}

	return config
}

// TwoFactorConfig returns a configuration with two-factor authentication enabled
func (tc *TestConfigurations) TwoFactorConfig() types.Config {
	config := tc.MinimalConfig()
	config.AuthConfig.EnableTwoFactor = true
	config.AuthConfig.TwoFactorMethod = "totp"
	return config
}

// EmailVerificationConfig returns a configuration with email verification enabled
func (tc *TestConfigurations) EmailVerificationConfig() types.Config {
	config := tc.MinimalConfig()
	config.AuthConfig.EnableEmailVerificationOnSignup = true
	config.AuthConfig.EmailVerificationURL = "http://localhost:8080/verify-email"
	return config
}

// RateLimitConfig returns a configuration with rate limiting enabled
func (tc *TestConfigurations) RateLimitConfig() types.Config {
	config := tc.MinimalConfig()
	config.EnableRateLimiter = true
	config.RateLimiter = &types.RateLimiterConfig{
		Routes: map[string]types.LimiterConfig{
			types.RouteRegister: {
				WindowSize:    30 * time.Second,
				MaxRequests:   10,
				BlockDuration: 1 * time.Minute,
			},
		},
	}
	return config
}

// RecaptchaConfig returns a configuration with reCAPTCHA enabled
func (tc *TestConfigurations) RecaptchaConfig() types.Config {
	config := tc.MinimalConfig()
	config.EnableRecaptcha = true
	config.RecaptchaConfig = &types.RecaptchaConfig{
		SecretKey: "test-secret-key",
		SiteKey:   "test-site-key",
	}
	return config
}

// SwaggerConfig returns a configuration with Swagger documentation enabled
func (tc *TestConfigurations) SwaggerConfig() types.Config {
	config := tc.MinimalConfig()
	config.Swagger.Enable = true
	config.Swagger.Title = "Test API"
	config.Swagger.Version = "1.0.0"
	config.Swagger.DocPath = "/docs"
	config.Swagger.Description = "Test API Description"
	config.Swagger.Host = "localhost:8080"
	return config
}

// CustomStorageConfig returns a configuration for custom storage testing
func (tc *TestConfigurations) CustomStorageConfig() types.Config {
	config := tc.MinimalConfig()
	config.EnableCustomStorageRepository = true
	return config
}

// InvalidConfigs returns various invalid configurations for testing validation
func (tc *TestConfigurations) InvalidConfigs() map[string]types.Config {
	return map[string]types.Config{
		"missing_server_type": func() types.Config {
			config := tc.MinimalConfig()
			config.Server.Type = ""
			return config
		}(),
		"missing_database_url": func() types.Config {
			config := tc.MinimalConfig()
			config.Database.URL = ""
			return config
		}(),
		"missing_database_type": func() types.Config {
			config := tc.MinimalConfig()
			config.Database.Type = ""
			return config
		}(),
		"missing_jwt_secret": func() types.Config {
			config := tc.MinimalConfig()
			config.JWTSecret = ""
			return config
		}(),
		"missing_cookie_name": func() types.Config {
			config := tc.MinimalConfig()
			config.AuthConfig.Cookie.Name = ""
			return config
		}(),
		"invalid_access_token_ttl": func() types.Config {
			config := tc.MinimalConfig()
			config.AuthConfig.Cookie.AccessTokenTTL = 0
			return config
		}(),
		"invalid_refresh_token_ttl": func() types.Config {
			config := tc.MinimalConfig()
			config.AuthConfig.Cookie.RefreshTokenTTL = 0
			return config
		}(),
		"missing_cookie_path": func() types.Config {
			config := tc.MinimalConfig()
			config.AuthConfig.Cookie.Path = ""
			return config
		}(),
		"invalid_cookie_max_age": func() types.Config {
			config := tc.MinimalConfig()
			config.AuthConfig.Cookie.MaxAge = 0
			return config
		}(),
		"invalid_hash_salt_length": func() types.Config {
			config := tc.MinimalConfig()
			config.PasswordPolicy.HashSaltLength = 0
			return config
		}(),
		"invalid_password_min_length": func() types.Config {
			config := tc.MinimalConfig()
			config.PasswordPolicy.MinLength = 0
			return config
		}(),
		"two_factor_without_method": func() types.Config {
			config := tc.MinimalConfig()
			config.AuthConfig.EnableTwoFactor = true
			config.AuthConfig.TwoFactorMethod = ""
			return config
		}(),
		"email_verification_without_url": func() types.Config {
			config := tc.MinimalConfig()
			config.AuthConfig.EnableEmailVerificationOnSignup = true
			config.AuthConfig.EmailVerificationURL = ""
			return config
		}(),
		"rate_limiter_without_config": func() types.Config {
			config := tc.MinimalConfig()
			config.EnableRateLimiter = true
			config.RateLimiter = nil
			return config
		}(),
		"recaptcha_without_config": func() types.Config {
			config := tc.MinimalConfig()
			config.EnableRecaptcha = true
			config.RecaptchaConfig = nil
			return config
		}(),
		"custom_jwt_claims_without_provider": func() types.Config {
			config := tc.MinimalConfig()
			config.EnableAddCustomJWTClaims = true
			config.CustomJWTClaimsProvider = nil
			return config
		}(),
		"swagger_without_title": func() types.Config {
			config := tc.MinimalConfig()
			config.Swagger.Enable = true
			config.Swagger.Title = ""
			return config
		}(),
		"swagger_without_version": func() types.Config {
			config := tc.MinimalConfig()
			config.Swagger.Enable = true
			config.Swagger.Title = "Test API"
			config.Swagger.Version = ""
			return config
		}(),
		"swagger_without_doc_path": func() types.Config {
			config := tc.MinimalConfig()
			config.Swagger.Enable = true
			config.Swagger.Title = "Test API"
			config.Swagger.Version = "1.0.0"
			config.Swagger.DocPath = ""
			return config
		}(),
		"swagger_without_description": func() types.Config {
			config := tc.MinimalConfig()
			config.Swagger.Enable = true
			config.Swagger.Title = "Test API"
			config.Swagger.Version = "1.0.0"
			config.Swagger.DocPath = "/docs"
			config.Swagger.Description = ""
			return config
		}(),
		"swagger_without_host": func() types.Config {
			config := tc.MinimalConfig()
			config.Swagger.Enable = true
			config.Swagger.Title = "Test API"
			config.Swagger.Version = "1.0.0"
			config.Swagger.DocPath = "/docs"
			config.Swagger.Description = "Test API Description"
			config.Swagger.Host = ""
			return config
		}(),
	}
}

// GetTestConfigurations returns a new instance of TestConfigurations
func GetTestConfigurations() *TestConfigurations {
	return &TestConfigurations{}
}
