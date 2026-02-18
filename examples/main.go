package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/bete7512/goauth/internal/modules/admin"
	"github.com/bete7512/goauth/internal/modules/audit"
	"github.com/bete7512/goauth/internal/modules/magiclink"
	"github.com/bete7512/goauth/internal/modules/notification"
	"github.com/bete7512/goauth/internal/modules/notification/services/senders"
	"github.com/bete7512/goauth/internal/modules/notification/templates"
	"github.com/bete7512/goauth/internal/modules/oauth"
	"github.com/bete7512/goauth/internal/modules/session"
	"github.com/bete7512/goauth/pkg/adapters/stdhttp"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/bete7512/goauth/storage"
	"github.com/joho/godotenv"
)

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
			EnableLoginAlerts:         false,
			EnablePasswordChangeAlert: true,
			EnableMagicLinkEmail:      true,
			EmailSender: senders.NewResendEmailSender(
				&senders.ResendConfig{
					APIKey:          resendAPIKey,
					DefaultFrom:     "goauth@beteg.dev",
					DefaultFromName: "Goauth",
				},
			),
			Branding: &templates.Branding{
				AppName:      "Go Auth",
				LogoURL:      "https://www.syncore-labs.com/logo.svg",
				PrimaryColor: "#006266",
				TextColor:    "#000",
				ContactEmail: "bete@goauth.io",
				DomainName:   "goauth.io",
			},
		},
	))

	authInstance.Use(magiclink.New(&config.MagicLinkModuleConfig{
		CallbackURL:  "http://localhost:3000",
		TokenExpiry:  time.Hour,
		AutoRegister: true,
	}, nil))
	// --- Option 1: Session-based auth (uncomment to use) ---
	authInstance.Use(session.New(&config.SessionModuleConfig{
		EnableSessionManagement: true,
		Strategy:                types.SessionStrategyCookieCache,
		CookieEncoding:          types.CookieEncodingCompact,
		CookieCacheTTL:          time.Hour,
		SensitivePaths:          []string{"admin/*"},
		SlidingExpiration:       true,
		UpdateAge:               30 * time.Minute,
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
	authInstance.On(types.EventSendMagicLink, func(ctx context.Context, e *types.Event) error {
		switch v := e.Data.(type) {

		case json.RawMessage:
			log.Printf("raw json: %s", string(v))

		case []byte:
			log.Printf("raw bytes: %s", string(v))

		default:
			log.Printf("unexpected data type: %T", v)
		}
		return nil
	})

	authInstance.On(types.EventBeforeLogin, func(ctx context.Context, e *types.Event) error {
		// time.Sleep(10 * time.Second)
		log.Println("beforelogin....................")
		return nil
	})
	authInstance.On(types.EventAfterLogin, func(ctx context.Context, e *types.Event) error {
		// time.Sleep(10 * time.Second)
		log.Println("afterelogin....................")
		return nil
	})

	// OAuth provider configuration
	oauthConfigs := map[string]*config.OAuthProviderConfig{
		"google": {
			Enabled:      true,
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			Scopes:       []string{"openid", "email", "profile"}, // Optional - uses defaults if empty
			RedirectURL:  "http://localhost:3000",
		},
	}

	authInstance.Use(oauth.New(&config.OAuthModuleConfig{
		Providers:              oauthConfigs,
		AllowSignup:            true, // Allow creating new users via OAuth
		AllowAccountLinking:    true, // Allow linking OAuth to existing accounts with same email
		TrustEmailVerification: true, // Trust OAuth provider's email verification
		StateTTL:               10 * time.Minute,
	}, nil))

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
	// --- Framework Integration via Adapters ---
	//
	// Each adapter is a separate Go module. Import only the one you need:
	//
	// net/http (stdlib):
	mux := http.NewServeMux()
	handler := stdhttp.Register(mux, authInstance)
	handler = LoggingMiddleware(handler)
	log.Println("Server running on :8080")
	http.ListenAndServe(":8080", handler)

	//
	// Gin:
	//   import "github.com/bete7512/goauth/pkg/adapters/ginadapter"
	// r := gin.Default()
	// ginadapter.Register(r, authInstance)
	// r.Run(":8080")
	//
	// Chi:
	//   import "github.com/bete7512/goauth/pkg/adapters/chiadapter"
	//   r := chi.NewRouter()
	//   chiadapter.Register(r, authInstance)
	//   http.ListenAndServe(":8080", r)
	//
	// Fiber:
	//   import "github.com/bete7512/goauth/pkg/adapters/fiberadapter"
	//   app := fiber.New()
	//   fiberadapter.Register(app, authInstance)
	//   app.Listen(":8080")
}
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// Call the next handler in the chain
		next.ServeHTTP(w, r)

		// Log details after the handler has finished
		duration := time.Since(startTime)
		// Use slog for structured, key-value pair logging
		log.Printf("method=%s path=%s ip=%s duration=%s",
			r.Method,
			r.URL.Path,
			r.RemoteAddr,
			duration,
		)

	})
}
