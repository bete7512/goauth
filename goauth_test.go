package goauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bete7512/goauth/api/core"
	"github.com/bete7512/goauth/interfaces"
	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRepositoryFactory is a mock implementation of RepositoryFactory
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

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByID(id string) (*models.User, error) {
	args := m.Called(id)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(email string) (*models.User, error) {
	args := m.Called(email)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) Update(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

// MockTokenRepository is a mock implementation of TokenRepository
type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) SaveToken(token *models.Token) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockTokenRepository) GetToken(tokenString string) (*models.Token, error) {
	args := m.Called(tokenString)
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenRepository) DeleteToken(tokenString string) error {
	args := m.Called(tokenString)
	return args.Error(0)
}

// MockRateLimiter is a mock implementation of RateLimiter
type MockRateLimiter struct {
	mock.Mock
}

func (m *MockRateLimiter) Allow(key string, config types.LimiterConfig) bool {
	args := m.Called(key, config)
	return args.Bool(0)
}

func (m *MockRateLimiter) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockCaptchaVerifier is a mock implementation of CaptchaVerifier
type MockCaptchaVerifier struct {
	mock.Mock
}

func (m *MockCaptchaVerifier) Verify(token string, remoteIP string) (bool, error) {
	args := m.Called(token, remoteIP)
	return args.Bool(0), args.Error(1)
}

// Test helper functions
func createTestConfig() types.Config {
	return types.Config{
		Server: types.ServerConfig{
			Type: "http",
			Port: 8080,
		},
		Database: types.DatabaseConfig{
			Type: "postgres",
			URL:  "postgres://test:test@localhost:5432/test",
		},
		JWTSecret: "test-secret-key",
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
		EnableRateLimiter: false,
		EnableRecaptcha:   false,
	}
}

func TestNewAuth(t *testing.T) {
	config := createTestConfig()

	// Test with valid config
	auth, err := NewAuth(config)
	assert.NoError(t, err)
	assert.NotNil(t, auth)
	assert.Equal(t, config, auth.Config)
}

func TestAuthService_RegisterBeforeHook(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	hook := func(w http.ResponseWriter, r *http.Request) (proceed bool, err error) {
		return true, nil
	}
	err = auth.RegisterBeforeHook("/login", hook)
	assert.NoError(t, err)
}

func TestAuthService_RegisterAfterHook(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	hook := func(w http.ResponseWriter, r *http.Request) (proceed bool, err error) {
		return true, nil
	}

	err = auth.RegisterAfterHook("/register", hook)
	assert.NoError(t, err)
}

func TestAuthService_GetSupportedFrameworks(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	frameworks := auth.GetSupportedFrameworks()
	assert.NotEmpty(t, frameworks)

	// Check that expected frameworks are included
	expectedFrameworks := []core.FrameworkType{
		core.FrameworkGin,
		core.FrameworkEcho,
		core.FrameworkChi,
		core.FrameworkFiber,
		core.FrameworkStandard,
	}

	for _, expected := range expectedFrameworks {
		assert.Contains(t, frameworks, expected)
	}
}

func TestAuthService_GetRoutes(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	routes := auth.GetRoutes()
	assert.NotEmpty(t, routes)

	// Check that we have both core and OAuth routes
	coreRoutes := auth.GetCoreRoutes()
	oauthRoutes := auth.GetOAuthRoutes()

	assert.NotEmpty(t, coreRoutes)
	assert.NotEmpty(t, oauthRoutes)
	assert.Equal(t, len(coreRoutes)+len(oauthRoutes), len(routes))
}

func TestAuthService_GetCoreRoutes(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	routes := auth.GetCoreRoutes()
	assert.NotEmpty(t, routes)

	// Check for expected core routes
	expectedPaths := []string{"/register", "/login", "/logout", "/refresh-token"}
	for _, path := range expectedPaths {
		found := false
		for _, route := range routes {
			if route.Path == path {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected route %s not found", path)
	}
}

func TestAuthService_GetOAuthRoutes(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	routes := auth.GetOAuthRoutes()
	assert.NotEmpty(t, routes)

	// Check for expected OAuth routes
	expectedProviders := []string{"google", "github", "facebook"}
	for _, provider := range expectedProviders {
		found := false
		for _, route := range routes {
			if route.Path == "/oauth/"+provider {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected OAuth route for %s not found", provider)
	}
}

func TestAuthService_SetupRoutes(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	// Test with Gin framework
	ginEngine := gin.New()
	err = auth.SetupRoutes(core.FrameworkGin, ginEngine)
	assert.NoError(t, err)

	// Test with invalid framework
	err = auth.SetupRoutes("invalid", ginEngine)
	assert.Error(t, err)
}

func TestAuthService_GetMiddleware(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	// Test with Gin framework
	middleware, err := auth.GetMiddleware(core.FrameworkGin)
	assert.NoError(t, err)
	assert.NotNil(t, middleware)

	// Test with invalid framework
	middleware, err = auth.GetMiddleware("invalid")
	assert.Error(t, err)
	assert.Nil(t, middleware)
}

func TestAuthService_GetGinAuthMiddleware(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	ginEngine := gin.New()
	middleware := auth.GetGinAuthMiddleware(ginEngine)
	assert.NotNil(t, middleware)

	// Test that middleware can be used
	ginEngine.Use(middleware)

	// Create a test request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	ginEngine.ServeHTTP(w, req)

	// Should not panic and should call Next()
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAuthService_GetGinAuthRoutes(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	ginEngine := gin.New()
	err = auth.GetGinAuthRoutes(ginEngine)
	assert.NoError(t, err)
}

func TestAuthService_GetHttpAuthMiddleware(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	})

	middleware := auth.GetHttpAuthMiddleware(testHandler)
	assert.NotNil(t, middleware)

	// Test that middleware can be used
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	middleware.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthService_GetHttpAuthRoutes(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	mux := http.NewServeMux()
	err = auth.GetHttpAuthRoutes(mux)
	assert.NoError(t, err)
}

func TestAuthService_SetupChiRoutes(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	// Create a mock Chi router
	mockRouter := &MockChiRouter{}

	err = auth.SetupChiRoutes(mockRouter)
	assert.NoError(t, err)
}

func TestAuthService_SetupEchoRoutes(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	// Create a mock Echo router
	mockRouter := &MockEchoRouter{}

	err = auth.SetupEchoRoutes(mockRouter)
	assert.NoError(t, err)
}

func TestAuthService_SetupFiberRoutes(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	// Create a mock Fiber router
	mockRouter := &MockFiberRouter{}

	err = auth.SetupFiberRoutes(mockRouter)
	assert.NoError(t, err)
}

func TestAuthService_SetupGorillaMuxRoutes(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	// Create a mock Gorilla Mux router
	mockRouter := &MockGorillaMuxRouter{}

	err = auth.SetupGorillaMuxRoutes(mockRouter)
	assert.NoError(t, err)
}

func TestAuthService_SetupStandardRoutes(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	mux := http.NewServeMux()
	err = auth.SetupStandardRoutes(mux)
	assert.NoError(t, err)
}

// Mock router implementations for testing
type MockChiRouter struct {
	mock.Mock
}

type MockEchoRouter struct {
	mock.Mock
}

type MockFiberRouter struct {
	mock.Mock
}

type MockGorillaMuxRouter struct {
	mock.Mock
}

func TestAuthService_InitAuthContext(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	// Test that authContext is initialized
	auth.initAuthContext()
	assert.NotNil(t, auth.authContext)
	assert.Equal(t, auth.Config, auth.authContext.Config)
	assert.Equal(t, auth.Repository, auth.authContext.Repository)
	assert.Equal(t, auth.HookManager, auth.authContext.HookManager)
	assert.Equal(t, auth.Logger, auth.authContext.Logger)
}

func TestAuthService_GetAuthAPI(t *testing.T) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)

	// Test that AuthAPI is initialized
	authAPI := auth.getAuthAPI()
	assert.NotNil(t, authAPI)

	// Test that it's a singleton
	authAPI2 := auth.getAuthAPI()
	assert.Equal(t, authAPI, authAPI2)
}

func TestAuthService_WithCustomRepository(t *testing.T) {
	config := createTestConfig()
	config.EnableCustomStorageRepository = true

	mockRepoFactory := &MockRepositoryFactory{}

	auth, err := NewBuilder().
		WithConfig(config).
		WithRepositoryFactory(mockRepoFactory).
		Build()

	assert.NoError(t, err)
	assert.NotNil(t, auth)
	assert.Equal(t, mockRepoFactory, auth.Repository)
}

func TestAuthService_WithCustomCaptchaVerifier(t *testing.T) {
	config := createTestConfig()
	config.EnableRecaptcha = true

	mockCaptchaVerifier := &MockCaptchaVerifier{}

	auth, err := NewBuilder().
		WithConfig(config).
		WithCaptchaVerifier(mockCaptchaVerifier).
		Build()

	assert.NoError(t, err)
	assert.NotNil(t, auth)
	assert.Equal(t, mockCaptchaVerifier, auth.RecaptchaManager)
}

// Benchmark tests
func BenchmarkNewAuth(b *testing.B) {
	config := createTestConfig()

	for i := 0; i < b.N; i++ {
		_, err := NewAuth(config)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetRoutes(b *testing.B) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		auth.GetRoutes()
	}
}

func BenchmarkGetCoreRoutes(b *testing.B) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		auth.GetCoreRoutes()
	}
}

func BenchmarkGetOAuthRoutes(b *testing.B) {
	config := createTestConfig()
	auth, err := NewAuth(config)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		auth.GetOAuthRoutes()
	}
}
