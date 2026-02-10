package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/bete7512/goauth/internal/modules/admin"
	"github.com/bete7512/goauth/internal/modules/audit"
	"github.com/bete7512/goauth/internal/modules/notification"
	"github.com/bete7512/goauth/internal/modules/notification/services/senders"
	"github.com/bete7512/goauth/internal/modules/notification/templates"
	"github.com/bete7512/goauth/internal/modules/session"
	"github.com/bete7512/goauth/internal/modules/stateless"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/bete7512/goauth/storage"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/joho/godotenv"
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

	// --- Option 1: Default worker pool backend (no config needed) ---
	// Events are processed in-memory by a goroutine pool (10 workers, 1000 queue).

	// --- Option 2: NATS JetStream backend (uncomment to use) ---
	// Durable, distributed event processing. Requires a running NATS server.
	//
	// natsBackend, err := NewNATSJetStreamBackend(context.Background(), &NATSConfig{
	// 	URL:      "nats://localhost:4222",
	// 	Username: "admin",
	// 	Password: "123456",
	// })
	// if err != nil {
	// 	log.Fatalf("Failed to create NATS backend: %v", err)
	// }
	//
	// // Start a consumer in a background goroutine to process events.
	// // In production, run this in a separate worker process.
	// go func() {
	// 	err := natsBackend.ConsumeEvents(context.Background(), "goauth-worker", func(ctx context.Context, payload EventPayload) error {
	// 		log.Printf("NATS event: type=%s id=%s", payload.Type, payload.ID)
	// 		return nil
	// 	})
	// 	if err != nil {
	// 		log.Printf("NATS consumer stopped: %v", err)
	// 	}
	// }()

	natsBackend, err := NewNATSJetStreamBackend(context.Background(), &NATSConfig{
		URL:      "nats://localhost:4222",
		Username: "admin",
		Password: "123456",
	})
	if err != nil {
		log.Fatalf("Failed to create NATS backend: %v", err)
	}
	// Create auth instance
	authInstance, err := auth.New(&config.Config{
		Storage:      store,
		AsyncBackend: natsBackend,
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
		APIURL:      "http://localhost:8080",
		BasePath:    "/api/v1",
		Core: &config.CoreConfig{
			RequireEmailVerification: true,  // Enable email verification
			RequirePhoneVerification: false, // Disable phone verification
			RequireUserName:          false, // Username is optional
			RequirePhoneNumber:       false, // Phone number is optional
			UniquePhoneNumber:        true,  // Phone numbers must be unique
		},
		// In production, replace "*" with your actual frontend origin
		CORS: &config.CORSConfig{
			Enabled:        true,
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders: []string{"Content-Type", "Authorization", "X-Captcha-Token", "X-CSRF-Token"},
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

	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on environment variables")
	}

	resendAPIKey := os.Getenv("RESEND_API_KEY")
	if resendAPIKey == "" {
		log.Fatal("RESEND_API_KEY is not set")
	}
	authInstance.Use(notification.New(
		&notification.Config{
			EnableWelcomeEmail:        true,
			EnablePasswordResetEmail:  true,
			EnableLoginAlerts:         true,
			EnablePasswordChangeAlert: true,
			EmailSender: senders.NewResendEmailSender(
				&senders.ResendConfig{
					APIKey:          resendAPIKey,
					DefaultFrom:     "goauth@beteg.dev",
					DefaultFromName: "Goauth",
				},
			),
			Branding: &templates.Branding{
				AppName:      "Go Auth",
				LogoURL:      "https://lab20101.nodeum.io/assets/ng/assets/logo-nodeum-white.svg",
				PrimaryColor: "#006266",
				TextColor:    "#000",
				ContactEmail: "bete@goauth.io",
				DomainName:   "goauth.io",
			},
		},
	))

	// --- Option 1: Session-based auth (uncomment to use) ---
	authInstance.Use(session.New(&config.SessionModuleConfig{
		EnableSessionManagement: true, // Enable session list/delete endpoints

	}, nil))

	// // csrf (HMAC-based double-submit cookie pattern)
	// authInstance.Use(csrf.New(&config.CSRFModuleConfig{
	// 	TokenExpiry: 2 * time.Hour,
	// 	Secure:      false, // set true in production
	// 	SameSite:    http.SameSiteLaxMode,
	// }))

	// Captcha protection using Cloudflare Turnstile test keys (always passes)
	// To test failure: change SiteKey to "2x00000000000000000000AB" and SecretKey to "2x0000000000000000000000000000000AB"
	// To use Google reCAPTCHA v3: set Provider to types.CaptchaProviderGoogle, add your keys, and set ScoreThreshold

	// authInstance.Use(captcha.New(&config.CaptchaModuleConfig{
	// 	Provider:      types.CaptchaProviderCloudflare,
	// 	SiteKey:       "1x00000000000000000000AA",            // Cloudflare test key (always passes)
	// 	SecretKey:     "1x0000000000000000000000000000000AA",  // Cloudflare test secret (always passes)
	// 	ApplyToRoutes: []types.RouteName{types.RouteSignup, types.RouteLogin},
	// }))
	authInstance.Use(admin.New(&admin.Config{}))
	// Pass nil to use default config which enables all event tracking
	authInstance.Use(audit.New(nil))

	// Register custom hooks (user-defined)
	authInstance.On(types.EventAfterLogin, func(ctx context.Context, e *types.Event) error {
		log.Println("✅ EventAfterLogin:", e.Type, e.Data)
		return nil
	})

	authInstance.On(types.EventAuthLoginSuccess, func(ctx context.Context, e *types.Event) error {
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

	// Handle CORS preflight at the Gin router level.
	// GoAuth's CORS middleware wraps route handlers, but Gin's method-based routing
	// returns 404 for OPTIONS requests before the handler (and its middleware) runs.
	// This middleware intercepts OPTIONS before route matching.
	corsConfig := auth.Config().CORS
	if corsConfig != nil && corsConfig.Enabled {
		r.Use(func(c *gin.Context) {
			if c.Request.Method == http.MethodOptions {
				origin := c.GetHeader("Origin")
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Access-Control-Allow-Methods", strings.Join(corsConfig.AllowedMethods, ", "))
				c.Header("Access-Control-Allow-Headers", strings.Join(corsConfig.AllowedHeaders, ", "))
				c.Header("Access-Control-Allow-Credentials", "true")
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
			c.Next()
		})
	}

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

	// Serve captcha test page at /captcha-test
	r.StaticFile("/captcha-test", "./captcha-test.html")

	log.Println("Captcha test page: http://localhost:8080/captcha-test")
	r.Run(":8080")
	return r
}
