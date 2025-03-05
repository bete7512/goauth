package examples

// example/main.go
import (
	"log"
	"net/http"
	"time"

	goauth "github.com/bete7512/go-auth/auth"
	"github.com/bete7512/go-auth/auth/types"
	"github.com/gin-gonic/gin"
)

func ginExample() {
	// Initialize configuration with Builder
	// authConfig, err := config.NewBuilder().
	// 	WithServer(types.GinServer, "/auth").
	// 	WithDatabase(types.DatabaseConfig{
	// 		Type:        types.PostgreSQL,
	// 		URL:         "postgres://postgres:password@localhost:5432/auth_db?sslmode=disable",
	// 		AutoMigrate: true,
	// 	}).
	// 	WithJWT("your-secret-key", 15*time.Minute, 7*24*time.Hour, 15).
	// 	WithPasswordPolicy(types.PasswordPolicy{
	// 		MinLength:      8,
	// 		RequireUpper:   true,
	// 		RequireLower:   true,
	// 		RequireNumber:  true,
	// 		RequireSpecial: true,
	// 	}).
	// 	// WithProvider(types.Google, types.ProviderConfig{)
	// 	WithCookie(true, "localhost").
	// 	Build()
	// if err != nil {
	// 	log.Fatalf("Failed to build auth config: %v", err)
	// }
	// Initialize configuration with struct
	config := types.Config{
		Database: types.DatabaseConfig{
			Type:        types.PostgreSQL,
			URL:         "postgres://postgres:password@localhost:5432/auth_db?sslmode=disable",
			AutoMigrate: true,
		},
		Server: types.ServerConfig{
			Type: types.GinServer,
		},
		EnableTwoFactor:         false,
		TwoFactorMethod:         "email",
		EnableEmailVerification: true,
		CookieSecure:            false,
		CookieDomain:            "localhost",
		EmailVerificationURL:    "http://localhost:8080/auth/verify-email",
		PasswordResetURL:        "http://localhost:8080/auth/reset-password",
		JWTSecret:               "your-secret-key",
		AccessTokenTTL:          15 * time.Minute,
		RefreshTokenTTL:         7 * 24 * time.Hour,
		PasswordPolicy: types.PasswordPolicy{
			MinLength:      8,
			RequireUpper:   true,
			RequireLower:   true,
			RequireNumber:  true,
			RequireSpecial: true,
		},
		Providers: types.ProvidersConfig{
			Enabled: []types.AuthProvider{types.Google},
			Google: types.ProviderConfig{
				ClientID:     "google-client-id",
				ClientSecret: "google-client-secret",
				RedirectURL:  "http://localhost:8080/auth/google/callback",
				Scopes:       []string{"email", "profile"},
			},
		},
	}
	// Initialize auth service
	authService, err := goauth.NewAuth(config)
	if err != nil {
		log.Fatalf("Failed to create auth service: %v", err)
	}

	// Register hooks for login route
	authService.RegisterBeforeHook(types.RouteLogin, func(w http.ResponseWriter, r *http.Request) (bool, error) {
		log.Println("Before login hook - Checking IP address...")
		// Example: IP restriction check
		ip := r.RemoteAddr
		// Add your custom logic here
		log.Printf("Login attempt from IP: %s", ip)
		return true, nil // Return true to continue, false to abort
	})

	authService.RegisterAfterHook(types.RouteLogin, func(w http.ResponseWriter, r *http.Request) (bool, error) {
		log.Println("After login hook - Recording successful login...")
		// Example: Log successful login
		// You might want to add audit logging, analytics, etc.
		return true, nil
	})

	// Register hooks for registration
	authService.RegisterBeforeHook(types.RouteRegister, func(w http.ResponseWriter, r *http.Request) (bool, error) {
		log.Println("Before registration hook - Additional validation...")
		// Example: Custom validation, rate limiting, etc.
		return true, nil
	})
	authService.RegisterAfterHook(types.RouteRegister, func(w http.ResponseWriter, r *http.Request) (bool, error) {
		log.Println("After registration hook - Sending welcome email...")
		// Example: Send welcome email to new user
		return true, nil
	})

	// Initialize Gin router
	router := gin.Default()
	// Set up auth routes
	middleWare := authService.GetGinAuthMiddleware(router)
	authService.GetGinAuthRoutes(router)
	protected := router.Group("/api")
	protected.Use(middleWare)
	protected.GET("/protected", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello from protected",
		})
	})
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	mux := http.NewServeMux()
	authService.GetHttpAuthRoutes(mux)

	// Apply middleware to handler
	mux.Handle("/api", authService.GetHttpAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello from protected"))
	})))
	// Start server
	log.Println("Starting server on :8080")
	err = http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

}
