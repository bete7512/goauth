package goauth

import (
	"context"
	"testing"
	"time"

	"github.com/bete7512/goauth/config"
	"github.com/bete7512/goauth/interfaces"
	"github.com/bete7512/goauth/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock implementations for testing
type MockRepositoryFactory struct {
	mock.Mock
}

func (m *MockRepositoryFactory) GetUserRepository() interfaces.UserRepository {
	args := m.Called()
	return args.Get(0).(interfaces.UserRepository)
}

func (m *MockRepositoryFactory) GetTokenRepository() interfaces.TokenRepository {
	args := m.Called()
	return args.Get(0).(interfaces.TokenRepository)
}

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) CreateUser(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) UpsertUserByEmail(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserByPhoneNumber(phoneNumber string) (*models.User, error) {
	args := m.Called(phoneNumber)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByEmail(email string) (*models.User, error) {
	args := m.Called(email)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByID(id string) (*models.User, error) {
	args := m.Called(id)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) UpdateUser(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteUser(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) GetAllUsers(filter interfaces.Filter) ([]*models.User, int64, error) {
	args := m.Called(filter)
	return args.Get(0).([]*models.User), args.Get(1).(int64), args.Error(2)
}

type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) SaveToken(userID, token string, tokenType models.TokenType, expiry time.Duration) error {
	args := m.Called(userID, token, tokenType, expiry)
	return args.Error(0)
}

func (m *MockTokenRepository) SaveTokenWithDeviceId(userID, token, deviceId string, tokenType models.TokenType, expiry time.Duration) error {
	args := m.Called(userID, token, deviceId, tokenType, expiry)
	return args.Error(0)
}

func (m *MockTokenRepository) GetTokenByUserID(userID string, tokenType models.TokenType) (*models.Token, error) {
	args := m.Called(userID, tokenType)
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenRepository) InvalidateToken(userID, token string, tokenType models.TokenType) error {
	args := m.Called(userID, token, tokenType)
	return args.Error(0)
}

func (m *MockTokenRepository) InvalidateAllTokens(userID string, tokenType models.TokenType) error {
	args := m.Called(userID, tokenType)
	return args.Error(0)
}

type MockCaptchaVerifier struct {
	mock.Mock
}

func (m *MockCaptchaVerifier) Verify(ctx context.Context, token string, remoteIP string) (bool, error) {
	args := m.Called(ctx, token, remoteIP)
	return args.Bool(0), args.Error(1)
}

// Test helper functions
func createValidConfig() config.Config {
	return config.Config{
		App: config.AppConfig{
			BasePath: "/api",
			Domain:   "localhost",
		},
		Server: config.ServerConfig{
			Type: "http",
			Port: 8080,
		},
		Database: config.DatabaseConfig{
			Type: "postgres",
			URL:  "postgres://test:test@localhost:5432/test",
		},
		AuthConfig: config.AuthConfig{
			JWT: config.JWTConfig{
				Secret:          "test-secret-key",
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 7 * 24 * time.Hour,
			},
			Cookie: config.CookieConfig{
				Name:   "auth_token",
				Path:   "/",
				MaxAge: 86400,
			},
		},
		Security: config.SecurityConfig{
			RateLimiter: config.RateLimiterConfig{
				Enabled: false,
			},
			Recaptcha: config.RecaptchaConfig{
				Enabled: false,
			},
		},
		Features: config.FeaturesConfig{
			EnableCustomStorage: false,
		},
		Providers: config.ProvidersConfig{
			Enabled: []config.AuthProvider{config.Google},
			Google: config.ProviderConfig{
				ClientID:     "google-client-id",
				ClientSecret: "google-secret",
				RedirectURL:  "http://localhost/google/callback",
			},
		},
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
	assert.Equal(t, config, builder)
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
	config.Features.EnableCustomStorage = true

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
	assert.NotNil(t, auth.Repository)
	assert.NotNil(t, auth.HookManager)
	assert.NotNil(t, auth.RateLimiter)
	assert.NotNil(t, auth.Logger)
}

func TestBuilder_Build_WithCustomRepository(t *testing.T) {
	config := createValidConfig()
	config.Features.EnableCustomStorage = true

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
	config.Security.Recaptcha.Enabled = true
	config.Security.Recaptcha.SecretKey = "test-secret"

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
	config.AuthConfig.JWT.Secret = ""

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
	config.AuthConfig.JWT.AccessTokenTTL = 0

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "access token TTL must be greater than 0")
}

func TestBuilder_validate_RefreshTokenTTLRequired(t *testing.T) {
	config := createValidConfig()
	config.AuthConfig.JWT.RefreshTokenTTL = 0

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
	config.AuthConfig.PasswordPolicy.HashSaltLength = 0

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "hash salt length must be greater than 0")
}

func TestBuilder_validate_CustomStorageRepositoryWithoutFactory(t *testing.T) {
	config := createValidConfig()
	config.Features.EnableCustomStorage = true

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "repository factory is required when EnableCustomStorage is true")
}

func TestBuilder_validate_RecaptchaWithoutConfig(t *testing.T) {
	config := createValidConfig()
	config.Security.Recaptcha.Enabled = true
	config.Security.Recaptcha.SecretKey = ""

	auth, err := NewBuilder().
		WithConfig(config).
		Build()

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "EnableRecaptcha is true, but RecaptchaConfig is not properly configured")
}

// Integration tests
func TestBuilder_CompleteValidConfig(t *testing.T) {
	conf := createValidConfig()
	conf.App.Swagger.Enable = true
	conf.App.Swagger.Title = "Test API"
	conf.App.Swagger.Version = "1.0.0"
	conf.App.Swagger.DocPath = "/docs"
	conf.App.Swagger.Description = "Test API Description"
	conf.App.Swagger.Host = "localhost:8080"
	conf.Providers.Enabled = []config.AuthProvider{config.Google}
	conf.Providers.Google = config.ProviderConfig{
		ClientID:     "google-client-id",
		ClientSecret: "google-secret",
		RedirectURL:  "http://localhost/google/callback",
	}

	auth, err := NewBuilder().
		WithConfig(conf).
		Build()
	assert.NoError(t, err)
	assert.NotNil(t, auth)
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
