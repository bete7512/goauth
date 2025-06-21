package goauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// Integration test configuration
func createIntegrationTestConfig() types.Config {
	return types.Config{
		Server: types.ServerConfig{
			Type: "http",
			Port: 8080,
		},
		Database: types.DatabaseConfig{
			Type: "postgres",
			URL:  "postgres://test:test@localhost:5432/test",
		},
		JWTSecret: "test-secret-key-32-chars-long-for-integration-tests",
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

// Test data structuresfi
type RegisterRequest struct {
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number"`
	Password    string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Message      string       `json:"message"`
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	User         *models.User `json:"user"`
}

// Integration test for Gin framework
func TestIntegration_GinFramework(t *testing.T) {
	config := createIntegrationTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)
	assert.NotNil(t, auth)

	// Set Gin to test mode
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Setup auth routes
	err = auth.GetGinAuthRoutes(router)
	assert.NoError(t, err)

	// Test registration endpoint
	t.Run("Register User", func(t *testing.T) {
		registerReq := RegisterRequest{
			FirstName:   "John",
			LastName:    "Doe",
			Email:       "john.doe@example.com",
			PhoneNumber: "123-456-7890",
			Password:    "Password123!",
		}

		jsonData, err := json.Marshal(registerReq)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/register", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)

		// Should return 200 or 201 for successful registration
		assert.Contains(t, []int{200, 201}, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)

		// Check response structure
		assert.Contains(t, response, "message")
		assert.Contains(t, response, "user")
	})

	// Test login endpoint
	t.Run("Login User", func(t *testing.T) {
		loginReq := LoginRequest{
			Email:    "john.doe@example.com",
			Password: "Password123!",
		}

		jsonData, err := json.Marshal(loginReq)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)

		// Should return 200 for successful login
		assert.Equal(t, 200, w.Code)

		var response AuthResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)

		// Check response structure
		assert.NotEmpty(t, response.Message)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.NotNil(t, response.User)
		assert.Equal(t, "john.doe@example.com", response.User.Email)
	})

	// Test protected endpoint with middleware
	t.Run("Protected Endpoint", func(t *testing.T) {
		// First login to get token
		loginReq := LoginRequest{
			Email:    "john.doe@example.com",
			Password: "Password123!",
		}

		jsonData, err := json.Marshal(loginReq)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)

		var loginResponse AuthResponse
		err = json.Unmarshal(w.Body.Bytes(), &loginResponse)
		assert.NoError(t, err)

		// Now test protected endpoint
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/api/v1/me", nil)
		req.Header.Set("Authorization", "Bearer "+loginResponse.AccessToken)

		router.ServeHTTP(w, req)

		// Should return 200 for authenticated request
		assert.Equal(t, 200, w.Code)

		var userResponse models.User
		err = json.Unmarshal(w.Body.Bytes(), &userResponse)
		assert.NoError(t, err)
		assert.Equal(t, "john.doe@example.com", userResponse.Email)
	})

	// Test logout endpoint
	t.Run("Logout User", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/logout", nil)

		router.ServeHTTP(w, req)

		// Should return 200 for successful logout
		assert.Equal(t, 200, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response, "message")
	})
}

// Integration test for HTTP framework
func TestIntegration_HTTPFramework(t *testing.T) {
	config := createIntegrationTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)
	assert.NotNil(t, auth)

	mux := http.NewServeMux()

	// Setup auth routes
	err = auth.GetHttpAuthRoutes(mux)
	assert.NoError(t, err)

	// Test registration endpoint
	t.Run("Register User HTTP", func(t *testing.T) {
		registerReq := RegisterRequest{
			FirstName:   "Jane",
			LastName:    "Smith",
			Email:       "jane.smith@example.com",
			PhoneNumber: "987-654-3210",
			Password:    "Password123!",
		}

		jsonData, err := json.Marshal(registerReq)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/register", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		mux.ServeHTTP(w, req)

		// Should return 200 or 201 for successful registration
		assert.Contains(t, []int{200, 201}, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)

		// Check response structure
		assert.Contains(t, response, "message")
		assert.Contains(t, response, "user")
	})

	// Test login endpoint
	t.Run("Login User HTTP", func(t *testing.T) {
		loginReq := LoginRequest{
			Email:    "jane.smith@example.com",
			Password: "Password123!",
		}

		jsonData, err := json.Marshal(loginReq)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		mux.ServeHTTP(w, req)

		// Should return 200 for successful login
		assert.Equal(t, 200, w.Code)

		var response AuthResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)

		// Check response structure
		assert.NotEmpty(t, response.Message)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.NotNil(t, response.User)
		assert.Equal(t, "jane.smith@example.com", response.User.Email)
	})
}

// Integration test for route discovery
func TestIntegration_RouteDiscovery(t *testing.T) {
	config := createIntegrationTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)
	assert.NotNil(t, auth)

	t.Run("Get All Routes", func(t *testing.T) {
		routes := auth.GetRoutes()
		assert.NotEmpty(t, routes)

		// Check that we have both core and OAuth routes
		coreRoutes := auth.GetCoreRoutes()
		oauthRoutes := auth.GetOAuthRoutes()

		assert.NotEmpty(t, coreRoutes)
		assert.NotEmpty(t, oauthRoutes)
		assert.Equal(t, len(coreRoutes)+len(oauthRoutes), len(routes))

		// Verify specific routes exist
		expectedCoreRoutes := []string{"/register", "/login", "/logout", "/refresh-token", "/me"}
		for _, expectedRoute := range expectedCoreRoutes {
			found := false
			for _, route := range coreRoutes {
				if route.Path == expectedRoute {
					found = true
					break
				}
			}
			assert.True(t, found, "Expected core route %s not found", expectedRoute)
		}

		// Verify OAuth routes exist
		expectedOAuthRoutes := []string{"/oauth/google", "/oauth/github", "/oauth/facebook"}
		for _, expectedRoute := range expectedOAuthRoutes {
			found := false
			for _, route := range oauthRoutes {
				if route.Path == expectedRoute {
					found = true
					break
				}
			}
			assert.True(t, found, "Expected OAuth route %s not found", expectedRoute)
		}
	})

	t.Run("Get Supported Frameworks", func(t *testing.T) {
		frameworks := auth.GetSupportedFrameworks()
		assert.NotEmpty(t, frameworks)

		expectedFrameworks := []string{"gin", "echo", "chi", "fiber", "standard"}
		for _, expectedFramework := range expectedFrameworks {
			found := false
			for _, framework := range frameworks {
				if string(framework) == expectedFramework {
					found = true
					break
				}
			}
			assert.True(t, found, "Expected framework %s not found", expectedFramework)
		}
	})
}

// Integration test for middleware functionality
func TestIntegration_MiddlewareFunctionality(t *testing.T) {
	config := createIntegrationTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)
	assert.NotNil(t, auth)

	t.Run("Gin Middleware", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		router := gin.New()

		// Get and apply middleware
		middleware := auth.GetGinAuthMiddleware(router)
		assert.NotNil(t, middleware)

		router.Use(middleware)

		// Add a test route
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "test"})
		})

		// Test middleware execution
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		// Should not panic and should return 200
		assert.Equal(t, 200, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "test", response["message"])
	})

	t.Run("HTTP Middleware", func(t *testing.T) {
		// Create a test handler
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(`{"message": "test"}`))
		})

		// Apply middleware
		middleware := auth.GetHttpAuthMiddleware(testHandler)
		assert.NotNil(t, middleware)

		// Test middleware execution
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		middleware.ServeHTTP(w, req)

		// Should return 200
		assert.Equal(t, 200, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "test", response["message"])
	})
}

// Integration test for hook functionality
func TestIntegration_HookFunctionality(t *testing.T) {
	config := createIntegrationTestConfig()
	auth, err := NewAuth(config)
	assert.NoError(t, err)
	assert.NotNil(t, auth)

	t.Run("Register Before Hook", func(t *testing.T) {
		hookCalled := false
		hook := func(w http.ResponseWriter, r *http.Request) (proceed bool, err error) {
			hookCalled = true
			return true, nil
		}

		err := auth.RegisterBeforeHook("/login", hook)
		assert.NoError(t, err)
		assert.True(t, hookCalled)
	})

	t.Run("Register After Hook", func(t *testing.T) {
		hookCalled := false
		hook := func(w http.ResponseWriter, r *http.Request) (proceed bool, err error) {
			hookCalled = true
			return true, nil
		}

		err := auth.RegisterAfterHook("/register", hook)
		assert.NoError(t, err)
		assert.True(t, hookCalled)
	})
}

// Benchmark integration tests
func BenchmarkIntegration_GinSetup(b *testing.B) {
	config := createIntegrationTestConfig()
	auth, err := NewAuth(config)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		gin.SetMode(gin.TestMode)
		router := gin.New()
		err := auth.GetGinAuthRoutes(router)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIntegration_HTTPSetup(b *testing.B) {
	config := createIntegrationTestConfig()
	auth, err := NewAuth(config)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		mux := http.NewServeMux()
		err := auth.GetHttpAuthRoutes(mux)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIntegration_RouteDiscovery(b *testing.B) {
	config := createIntegrationTestConfig()
	auth, err := NewAuth(config)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		auth.GetRoutes()
		auth.GetCoreRoutes()
		auth.GetOAuthRoutes()
	}
}
