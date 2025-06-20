package goauth

import (
	"testing"

	"github.com/bete7512/goauth/types"
	"github.com/stretchr/testify/assert"
)

// Test helper functions
func createValidConfig() types.Config {
	return types.Config{
		Server: types.ServerConfig{
			Type: "http",
			Port: 8080,
		},
		Database: types.DatabaseConfig{
			Type: "postgres",
			URL:  "postgres://test:test@localhost:5432/test",
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
			EnableEmailVerification: false,
		},
		PasswordPolicy: types.PasswordPolicy{
			HashSaltLength: 16,
			MinLength:      8,
		},
		EnableRateLimiter:             false,
		EnableRecaptcha:               false,
		EnableCustomStorageRepository: false,
	}
}

func TestNewBuilder(t *testing.T) {
	builder := NewBuilder()
	assert.NotNil(t, builder)
	assert.IsType(t, &Builder{}, builder)
}

func TestBuilder_WithConfig(t *testing.T) {
	builder := NewBuilder()
	config := createValidConfig()

	builder = builder.WithConfig(config)
	assert.Equal(t, config, builder.config)
}

func TestBuilder_WithRepositoryFactory(t *testing.T) {
	builder := NewBuilder()
	mockRepo := &MockRepositoryFactory{}

	builder = builder.WithRepositoryFactory(mockRepo)
	assert.Equal(t, mockRepo, builder.repoFactory)
}

func TestBuilder_WithCaptchaVerifier(t *testing.T) {
	builder := NewBuilder()
	mockCaptcha := &MockCaptchaVerifier{}

	builder = builder.WithCaptchaVerifier(mockCaptcha)
	assert.Equal(t, mockCaptcha, builder.captchaVerifier)
}

func TestBuilder_Build_Success(t *testing.T) {
	config := createValidConfig()
	config.EnableCustomStorageRepository = true

	mockRepo := &MockRepositoryFactory{}
	mockUserRepo := &MockUserRepository{}
	mockTokenRepo := &MockTokenRepository{}

	mockRepo.On("GetUserRepository").Return(mockUserRepo)
	mockRepo.On("GetTokenRepository").Return(mockTokenRepo)

	auth, err := NewBuilder().
		WithConfig(config).
		WithRepositoryFactory(mockRepo).
		Build()

	assert.NoError(t, err)
	assert.NotNil(t, auth)
	assert.Equal(t, config, auth.Config)
	assert.NotNil(t, auth.Repository)
	assert.NotNil(t, auth.HookManager)
	assert.NotNil(t, auth.RateLimiter)
	assert.NotNil(t, auth.Logger)
}

func TestBuilder_Build_WithCustomRepository(t *testing.T) {
	config := createValidConfig()
	config.EnableCustomStorageRepository = true

	mockRepo := &MockRepositoryFactory{}

	auth, err := NewBuilder().
		WithConfig(config).
		WithRepositoryFactory(mockRepo).
		Build()

	assert.NoError(t, err)
	assert.NotNil(t, auth)
	assert.Equal(t, mockRepo, auth.Repository)
}

func TestBuilder_Build_WithCustomCaptchaVerifier(t *testing.T) {
	config := createValidConfig()
	config.EnableRecaptcha = true
	config.RecaptchaConfig = &types.RecaptchaConfig{
		SecretKey: "test-secret",
		SiteKey:   "test-site-key",
	}

	mockCaptcha := &MockCaptchaVerifier{}

	auth, err := NewBuilder().
		WithConfig(config).
		WithCaptchaVerifier(mockCaptcha).
		Build()

	assert.NoError(t, err)
	assert.NotNil(t, auth)
	assert.Equal(t, mockCaptcha, auth.RecaptchaManager)
}

func TestBuilder_Build_WithPreviousError(t *testing.T) {
	builder := NewBuilder()
	builder.err = assert.AnError

	auth, err := builder.Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "builder has previous error")
}

// Validation tests
func TestBuilder_validate_ServerTypeRequired(t *testing.T) {
	config := createValidConfig()
	config.Server.Type = ""

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "server type is required")
}

func TestBuilder_validate_DatabaseURLRequired(t *testing.T) {
	config := createValidConfig()
	config.Database.URL = ""

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "database URL is required")
}

func TestBuilder_validate_DatabaseTypeRequired(t *testing.T) {
	config := createValidConfig()
	config.Database.Type = ""

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "database type is required")
}

func TestBuilder_validate_JWTSecretRequired(t *testing.T) {
	config := createValidConfig()
	config.JWTSecret = ""

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "JWT secret is required")
}

func TestBuilder_validate_CookieNameRequired(t *testing.T) {
	config := createValidConfig()
	config.AuthConfig.Cookie.Name = ""

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "cookie name is required")
}

func TestBuilder_validate_AccessTokenTTLRequired(t *testing.T) {
	config := createValidConfig()
	config.AuthConfig.Cookie.AccessTokenTTL = 0

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "access token TTL must be greater than 0")
}

func TestBuilder_validate_RefreshTokenTTLRequired(t *testing.T) {
	config := createValidConfig()
	config.AuthConfig.Cookie.RefreshTokenTTL = 0

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "refresh token TTL must be greater than 0")
}

func TestBuilder_validate_CookiePathRequired(t *testing.T) {
	config := createValidConfig()
	config.AuthConfig.Cookie.Path = ""

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "cookie path is required")
}

func TestBuilder_validate_CookieMaxAgeRequired(t *testing.T) {
	config := createValidConfig()
	config.AuthConfig.Cookie.MaxAge = 0

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "max cookie age must be greater than 0")
}

func TestBuilder_validate_HashSaltLengthRequired(t *testing.T) {
	config := createValidConfig()
	config.PasswordPolicy.HashSaltLength = 0

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "hash salt length must be greater than 0")
}

func TestBuilder_validate_PasswordMinLengthRequired(t *testing.T) {
	config := createValidConfig()
	config.PasswordPolicy.MinLength = 0

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "password minimum length must be greater than 0")
}

func TestBuilder_validate_TwoFactorMethodRequired(t *testing.T) {
	config := createValidConfig()
	config.AuthConfig.EnableTwoFactor = true
	config.AuthConfig.TwoFactorMethod = ""

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "two-factor method is required when two-factor authentication is enabled")
}

func TestBuilder_validate_EmailVerificationURLRequired(t *testing.T) {
	config := createValidConfig()
	config.AuthConfig.EnableEmailVerification = true
	config.AuthConfig.EmailVerificationURL = ""

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "email verification URL is required when email verification is enabled")
}

func TestBuilder_validate_EmailSenderRequired(t *testing.T) {
	config := createValidConfig()
	config.AuthConfig.EnableEmailVerification = true
	config.AuthConfig.EmailVerificationURL = "http://example.com/verify"
	config.EmailSender = nil

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "email sender is required when email verification is enabled")
}

func TestBuilder_validate_SMSSenderRequired(t *testing.T) {
	config := createValidConfig()
	config.AuthConfig.EnableSmsVerification = true
	config.SMSSender = nil

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "SMS sender is required when SMS verification is enabled")
}

func TestBuilder_validate_RateLimiterConfigRequired(t *testing.T) {
	config := createValidConfig()
	config.EnableRateLimiter = true
	config.RateLimiter = nil

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "rate limiter configuration is required when rate limiting is enabled")
}

func TestBuilder_validate_CustomJWTClaimsProviderRequired(t *testing.T) {
	config := createValidConfig()
	config.EnableAddCustomJWTClaims = true
	config.CustomJWTClaimsProvider = nil

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "custom JWT claims provider is required when custom JWT claims are enabled")
}

func TestBuilder_validate_SwaggerTitleRequired(t *testing.T) {
	config := createValidConfig()
	config.Swagger.Enable = true
	config.Swagger.Title = ""

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "swagger title is required when swagger is enabled")
}

func TestBuilder_validate_SwaggerVersionRequired(t *testing.T) {
	config := createValidConfig()
	config.Swagger.Enable = true
	config.Swagger.Title = "Test API"
	config.Swagger.Version = ""

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "swagger version is required when swagger is enabled")
}

func TestBuilder_validate_SwaggerDocPathRequired(t *testing.T) {
	config := createValidConfig()
	config.Swagger.Enable = true
	config.Swagger.Title = "Test API"
	config.Swagger.Version = "1.0.0"
	config.Swagger.DocPath = ""

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "swagger doc path is required when swagger is enabled")
}

func TestBuilder_validate_SwaggerDescriptionRequired(t *testing.T) {
	config := createValidConfig()
	config.Swagger.Enable = true
	config.Swagger.Title = "Test API"
	config.Swagger.Version = "1.0.0"
	config.Swagger.DocPath = "/docs"
	config.Swagger.Description = ""

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "swagger description is required when swagger is enabled")
}

func TestBuilder_validate_SwaggerHostRequired(t *testing.T) {
	config := createValidConfig()
	config.Swagger.Enable = true
	config.Swagger.Title = "Test API"
	config.Swagger.Version = "1.0.0"
	config.Swagger.DocPath = "/docs"
	config.Swagger.Description = "Test API Description"
	config.Swagger.Host = ""

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "swagger host is required when swagger is enabled")
}

// OAuth provider validation tests
func TestBuilder_validateProviders_Google(t *testing.T) {
	config := createValidConfig()
	config.Providers.Enabled = []types.AuthProvider{types.Google}
	config.Providers.Google = types.ProviderConfig{
		ClientID:     "",
		ClientSecret: "secret",
		RedirectURL:  "http://localhost/callback",
	}

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "client ID is required for OAuth provider: google")
}

func TestBuilder_validateProviders_GitHub(t *testing.T) {
	config := createValidConfig()
	config.Providers.Enabled = []types.AuthProvider{types.GitHub}
	config.Providers.GitHub = types.ProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "",
		RedirectURL:  "http://localhost/callback",
	}

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "client secret is required for OAuth provider: github")
}

func TestBuilder_validateProviders_Facebook(t *testing.T) {
	config := createValidConfig()
	config.Providers.Enabled = []types.AuthProvider{types.Facebook}
	config.Providers.Facebook = types.ProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "secret",
		RedirectURL:  "",
	}

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "redirect URL is required for OAuth provider: facebook")
}

func TestBuilder_validateProviders_UnsupportedProvider(t *testing.T) {
	config := createValidConfig()
	config.Providers.Enabled = []types.AuthProvider{"unsupported"}

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "unsupported OAuth provider: unsupported")
}

func TestBuilder_validateProviders_ValidProviders(t *testing.T) {
	config := createValidConfig()
	config.Providers.Enabled = []types.AuthProvider{types.Google, types.GitHub}
	config.Providers.Google = types.ProviderConfig{
		ClientID:     "google-client-id",
		ClientSecret: "google-secret",
		RedirectURL:  "http://localhost/google/callback",
	}
	config.Providers.GitHub = types.ProviderConfig{
		ClientID:     "github-client-id",
		ClientSecret: "github-secret",
		RedirectURL:  "http://localhost/github/callback",
	}

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.NoError(t, err)
	assert.NotNil(t, auth)
}

func TestBuilder_validate_CustomStorageRepositoryWithoutFactory(t *testing.T) {
	config := createValidConfig()
	config.EnableCustomStorageRepository = true

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "repository factory is required when EnableCustomStorageRepository is true")
}

func TestBuilder_validate_RecaptchaWithoutConfig(t *testing.T) {
	config := createValidConfig()
	config.EnableRecaptcha = true
	config.RecaptchaConfig = nil

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "EnableRecaptcha is true, but RecaptchaConfig is nil")
}

// Integration tests
func TestBuilder_CompleteValidConfig(t *testing.T) {
	config := createValidConfig()
	config.Swagger.Enable = true
	config.Swagger.Title = "Test API"
	config.Swagger.Version = "1.0.0"
	config.Swagger.DocPath = "/docs"
	config.Swagger.Description = "Test API Description"
	config.Swagger.Host = "localhost:8080"

	config.Providers.Enabled = []types.AuthProvider{types.Google}
	config.Providers.Google = types.ProviderConfig{
		ClientID:     "google-client-id",
		ClientSecret: "google-secret",
		RedirectURL:  "http://localhost/google/callback",
	}

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.NoError(t, err)
	assert.NotNil(t, auth)
	assert.Equal(t, config, auth.Config)
}

// Benchmark tests
func BenchmarkNewBuilder(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewBuilder()
	}
}

func BenchmarkBuilder_Build(b *testing.B) {
	config := createValidConfig()

	for i := 0; i < b.N; i++ {
		_, err := NewBuilder().
			WithConfig(config).
			Build()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuilder_WithConfig(b *testing.B) {
	config := createValidConfig()

	for i := 0; i < b.N; i++ {
		NewBuilder().WithConfig(config)
	}
}

func BenchmarkBuilder_WithRepositoryFactory(b *testing.B) {
	mockRepo := &MockRepositoryFactory{}

	for i := 0; i < b.N; i++ {
		NewBuilder().WithRepositoryFactory(mockRepo)
	}
}

func BenchmarkBuilder_WithCaptchaVerifier(b *testing.B) {
	mockCaptcha := &MockCaptchaVerifier{}

	for i := 0; i < b.N; i++ {
		NewBuilder().WithCaptchaVerifier(mockCaptcha)
	}
}
