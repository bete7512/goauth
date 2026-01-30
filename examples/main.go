package main

import (
	"context"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/bete7512/goauth/internal/modules/stateless"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/bete7512/goauth/storage"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
)

// pathParamRegex matches Go 1.22+ / Chi-style path parameters like {id}
var pathParamRegex = regexp.MustCompile(`\{(\w+)\}`)

// toColonParams converts {param} to :param for Gin and Fiber routers
func toColonParams(path string) string {
	return pathParamRegex.ReplaceAllString(path, ":$1")
}

func main() {
	// Create storage instance using factory
	// Option 1: Use built-in GORM storage
	store, err := storage.NewGormStorage(storage.GormConfig{
		Dialect:      types.DialectTypePostgres,
		DSN:          "host=localhost user=postgres password=password dbname=authdb1 port=5432 sslmode=disable",
		LogLevel:     "warn",
		MaxOpenConns: 25,
		MaxIdleConns: 5,
	})
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	// Create auth instance
	authInstance, err := auth.New(&config.Config{
		Storage: store,
		Security: types.SecurityConfig{
			JwtSecretKey:  "your-secret-key-change-in-production",
			EncryptionKey: "your-encryption-key-change-in-production",
			Session: types.SessionConfig{
				Name:            "session_token",
				SessionTTL:      30 * 24 * time.Hour,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 7 * 24 * time.Hour,
			},
			PasswordPolicy: types.PasswordPolicy{
				MinLength:        4,
				MaxLength:        16,
				RequireUppercase: false,
				RequireSpecial:   false,
			},
		},
		AutoMigrate: true,
		BasePath:    "/api/v1",
		Core: &config.CoreConfig{
			RequireEmailVerification: true,  // Enable email verification
			RequirePhoneVerification: false, // Disable phone verification
			RequireUserName:          false, // Username is optional
			RequirePhoneNumber:       false, // Phone number is optional
			UniquePhoneNumber:        true,  // Phone numbers must be unique
		},
		FrontendConfig: &config.FrontendConfig{
			URL:                     "http://localhost:3000",
			Domain:                  "localhost",
			ResetPasswordPath:       "/reset-password",
			VerifyEmailCallbackPath: "/verify-email",
			LoginPath:               "/login",
			SignupPath:              "/signup",
			LogoutPath:              "/logout",
			ProfilePath:             "/profile",
			ChangePasswordPath:      "/change-password",
		},
	})
	if err != nil {
		log.Fatalf("Failed to create auth: %v", err)
	}

	// --- Option 1: Session-based auth (uncomment to use) ---
	// authInstance.Use(session.New(&config.SessionModuleConfig{
	// 	EnableSessionManagement: true, // Enable session list/delete endpoints

	// }, nil))

	

	// Register custom hooks (user-defined)
	authInstance.On(types.EventBeforeSignup, func(ctx context.Context, e *types.Event) error {
		log.Println("Before signup event:", e.Type, e.Data)
		return nil
	})

	// Initialize after all modules are registered
	if err := authInstance.Initialize(context.Background()); err != nil {
		log.Fatalf("Failed to initialize auth: %v", err)
	}

	// Enable swagger after initialization
	if err := authInstance.EnableSwagger(
		types.SwaggerConfig{
			Title:       "GoAuth Docs",
			Description: "GoAuth Documentation",
			Version:     "1.0.0",
			Path:        "/api/v1/docs",
			Servers: []types.SwaggerServer{
				{URL: "http://localhost:8080", Description: "Development Server"},
				{URL: "https://goauth.com", Description: "Production Server"},
			},
		},
	); err != nil {
		log.Fatalf("Failed to enable swagger: %v", err)
	}

	// Choose your server
	server := "gin"
	switch server {
	case "http":
		mux := http.NewServeMux()
		for _, route := range authInstance.Routes() {
			// Go 1.22+ ServeMux: "METHOD /path" for method-specific routing
			pattern := route.Method + " " + route.Path
			mux.HandleFunc(pattern, route.Handler)
		}
		log.Println("Server running on :8080")
		http.ListenAndServe(":8080", mux)
	case "fiber":
		fiberHandler(authInstance)
	case "chi":
		chiHandler(authInstance)
	case "gin":
		ginHandler(authInstance)
	}
}

// Example: Stateless authentication setup
func exampleStatelessSetup(store types.Storage) *auth.Auth {
	authInstance, _ := auth.New(&config.Config{
		Storage: store,
		Security: types.SecurityConfig{
			JwtSecretKey:  "your-secret-key",
			EncryptionKey: "your-encryption-key",
			Session: types.SessionConfig{
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 7 * 24 * time.Hour,
			},
		},
		AutoMigrate: true,
		BasePath:    "/api/v1",
	})

	// Use stateless JWT authentication
	authInstance.Use(stateless.New(&config.StatelessModuleConfig{
		RefreshTokenRotation: true,
	}, nil))

	authInstance.Initialize(context.Background())
	return authInstance
}

func fiberHandler(auth *auth.Auth) *fiber.App {
	fiber := fiber.New()
	for _, route := range auth.Routes() {
		// Fiber uses :param syntax, convert from {param}
		path := toColonParams(route.Path)
		switch route.Method {
		case http.MethodGet:
			fiber.Get(path, adaptor.HTTPHandler(route.Handler))
		case http.MethodPost:
			fiber.Post(path, adaptor.HTTPHandler(route.Handler))
		case http.MethodPut:
			fiber.Put(path, adaptor.HTTPHandler(route.Handler))
		case http.MethodDelete:
			fiber.Delete(path, adaptor.HTTPHandler(route.Handler))
		case http.MethodPatch:
			fiber.Patch(path, adaptor.HTTPHandler(route.Handler))
		case http.MethodOptions:
			fiber.Options(path, adaptor.HTTPHandler(route.Handler))
		}
	}
	fiber.Use(auth.RequireAuth)
	fiber.Listen(":8080")
	return fiber
}

func chiHandler(auth *auth.Auth) *chi.Mux {
	router := chi.NewRouter()
	for _, route := range auth.Routes() {
		switch route.Method {
		case http.MethodGet:
			router.Get(route.Path, route.Handler)
		case http.MethodPost:
			router.Post(route.Path, route.Handler)
		case http.MethodPut:
			router.Put(route.Path, route.Handler)
		case http.MethodDelete:
			router.Delete(route.Path, route.Handler)
		case http.MethodPatch:
			router.Patch(route.Path, route.Handler)
		case http.MethodOptions:
			router.Options(route.Path, route.Handler)
		}
	}
	router.Use(auth.RequireAuth)
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, World!"))
	})
	return router
}

func ginHandler(auth *auth.Auth) *gin.Engine {
	r := gin.Default()
	for _, route := range auth.Routes() {
		// Gin uses :param syntax, convert from {param}
		path := toColonParams(route.Path)
		switch route.Method {
		case http.MethodGet:
			r.GET(path, gin.WrapF(route.Handler))
		case http.MethodPost:
			r.POST(path, gin.WrapF(route.Handler))
		case http.MethodPut:
			r.PUT(path, gin.WrapF(route.Handler))
		case http.MethodDelete:
			r.DELETE(path, gin.WrapF(route.Handler))
		case http.MethodPatch:
			r.PATCH(path, gin.WrapF(route.Handler))
		case http.MethodOptions:
			r.OPTIONS(path, gin.WrapF(route.Handler))
		}
	}
	r.Run(":8080")
	return r
}
