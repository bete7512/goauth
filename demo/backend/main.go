package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/adapters/stdhttp"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/modules/admin"
	"github.com/bete7512/goauth/pkg/modules/audit"
	"github.com/bete7512/goauth/pkg/modules/magiclink"
	"github.com/bete7512/goauth/pkg/modules/notification"
	"github.com/bete7512/goauth/pkg/modules/notification/senders"
	"github.com/bete7512/goauth/pkg/modules/oauth"
	"github.com/bete7512/goauth/pkg/modules/organization"
	"github.com/bete7512/goauth/pkg/modules/session"
	"github.com/bete7512/goauth/pkg/modules/twofactor"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/bete7512/goauth/storage"
)

func main() {
	databaseURL := requireEnv("DATABASE_URL")
	jwtSecret := requireEnv("JWT_SECRET_KEY")
	encryptionKey := requireEnv("ENCRYPTION_KEY")
	// API_URL: explicit env, or Render's auto-set RENDER_EXTERNAL_URL, or localhost
	apiURL := ensureHTTPS(envOr("API_URL", envOr("RENDER_EXTERNAL_URL", "http://localhost:8080")))
	frontendURL := ensureHTTPS(envOr("FRONTEND_URL", "http://localhost:3000"))
	port := envOr("PORT", "8080")

	store, err := storage.NewGormStorage(storage.GormConfig{
		Dialect:      types.DialectTypePostgres,
		DSN:          databaseURL,
		LogLevel:     "warn",
		MaxOpenConns: 25,
		MaxIdleConns: 5,
	})
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	authInstance, err := auth.New(&config.Config{
		Storage: store,
		Security: types.SecurityConfig{
			JwtSecretKey:  jwtSecret,
			EncryptionKey: encryptionKey,
			AuthMode:      types.AuthModeBoth,
			Session: types.SessionConfig{
				Name:            "session_token",
				SessionTTL:      30 * 24 * time.Hour,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 7 * 24 * time.Hour,
			},
			PasswordPolicy: types.PasswordPolicy{
				MinLength:        8,
				MaxLength:        128,
				RequireUppercase: true,
				RequireSpecial:   false,
			},
		},
		Migration: config.MigrationConfig{
			Auto: true,
		},
		APIURL:   apiURL,
		BasePath: "/api/v1",
		Core: &config.CoreConfig{
			RequireEmailVerification: true,
			RequirePhoneVerification: false,
			RequireUserName:          false,
			RequirePhoneNumber:       false,
			UniquePhoneNumber:        true,
		},
		FrontendConfig: &config.FrontendConfig{
			URL:                     frontendURL,
			Domain:                  "",
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

	// Session module (always enabled)
	authInstance.Use(session.New(&config.SessionModuleConfig{
		EnableSessionManagement: true,
		Strategy:                types.SessionStrategyCookieCache,
		CookieEncoding:          types.CookieEncodingCompact,
		CookieCacheTTL:          time.Hour,
		SlidingExpiration:       true,
		UpdateAge:               30 * time.Minute,
	}, nil))

	// Admin module
	authInstance.Use(admin.New(&admin.Config{}))

	// Audit module (default config: all events tracked)
	authInstance.Use(audit.New(nil))

	// Organization module
	authInstance.Use(organization.New(&organization.Config{}))

	// Magic link module
	authInstance.Use(magiclink.New(&config.MagicLinkModuleConfig{
		CallbackURL:  frontendURL,
		TokenExpiry:  time.Hour,
		AutoRegister: true,
	}, nil))

	// Two-factor authentication
	authInstance.Use(twofactor.New(&config.TwoFactorConfig{
		Issuer: "GoAuth Demo",
	}))

	// Notification module (conditional on RESEND_API_KEY)
	if resendKey := os.Getenv("RESEND_API_KEY"); resendKey != "" {
		log.Println("Enabling notification module (Resend)")
		authInstance.Use(notification.New(&notification.Config{
			EnableWelcomeEmail:        true,
			EnablePasswordResetEmail:  true,
			EnableLoginAlerts:         false,
			EnablePasswordChangeAlert: true,
			EnableMagicLinkEmail:      true,
			EmailSender: senders.NewResendEmailSender(&senders.ResendConfig{
				APIKey:          resendKey,
				DefaultFrom:     envOr("EMAIL_FROM", "noreply@example.com"),
				DefaultFromName: envOr("EMAIL_FROM_NAME", "GoAuth Demo"),
			}),
			Branding: &notification.Branding{
				AppName:      "GoAuth Demo",
				PrimaryColor: "#006266",
				TextColor:    "#000",
				ContactEmail: envOr("EMAIL_FROM", "noreply@example.com"),
			},
		}))
	} else {
		log.Println("Skipping notification module (RESEND_API_KEY not set)")
	}

	// OAuth module (conditional on provider credentials)
	oauthProviders := make(map[string]*config.OAuthProviderConfig)

	if clientID, clientSecret := os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET"); clientID != "" && clientSecret != "" {
		log.Println("Enabling Google OAuth")
		oauthProviders["google"] = &config.OAuthProviderConfig{
			Enabled:      true,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       []string{"openid", "email", "profile"},
			RedirectURL:  frontendURL,
		}
	}

	if clientID, clientSecret := os.Getenv("GITHUB_CLIENT_ID"), os.Getenv("GITHUB_CLIENT_SECRET"); clientID != "" && clientSecret != "" {
		log.Println("Enabling GitHub OAuth")
		oauthProviders["github"] = &config.OAuthProviderConfig{
			Enabled:      true,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       []string{"user:email"},
			RedirectURL:  frontendURL,
		}
	}

	if len(oauthProviders) > 0 {
		authInstance.Use(oauth.New(&config.OAuthModuleConfig{
			Providers:              oauthProviders,
			AllowSignup:            true,
			AllowAccountLinking:    true,
			TrustEmailVerification: true,
			StateTTL:               10 * time.Minute,
		}, nil))
	} else {
		log.Println("Skipping OAuth module (no provider credentials set)")
	}

	// Initialize all modules
	if err := authInstance.Initialize(context.Background()); err != nil {
		log.Fatalf("Failed to initialize auth: %v", err)
	}

	// Enable OpenAPI documentation
	if err := authInstance.OpenAPI(types.OpenAPIConfig{
		Title:       "GoAuth Demo API",
		Description: "GoAuth authentication library demo",
		Version:     "1.0.0",
		Path:        "/api/v1/docs",
		Servers: []types.OpenAPIServer{
			{URL: apiURL, Description: "API Server"},
		},
	}); err != nil {
		log.Fatalf("Failed to enable OpenAPI: %v", err)
	}

	// Register routes with stdlib HTTP
	mux := http.NewServeMux()
	handler := stdhttp.Register(mux, authInstance)
	handler = corsMiddleware(handler, frontendURL)
	handler = loggingMiddleware(handler)

	log.Printf("GoAuth demo server starting on :%s", port)
	log.Printf("API docs: %s/api/v1/docs", apiURL)
	log.Printf("Frontend: %s", frontendURL)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func requireEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("Required environment variable %s is not set", key)
	}
	return val
}

func envOr(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// ensureHTTPS adds https:// prefix if the URL has no scheme.
// Render's fromService gives bare hostnames like "goauth-api-xxxx.onrender.com".
func ensureHTTPS(url string) string {
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return url
	}
	// Strip port 443 if present (Render sometimes includes it)
	url = strings.TrimSuffix(url, ":443")
	return "https://" + url
}

func corsMiddleware(next http.Handler, frontendURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// Allow the configured frontend URL and localhost for development
		if origin == frontendURL || origin == "http://localhost:3000" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Captcha-Token, X-CSRF-Token")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: 200}
		start := time.Now()
		next.ServeHTTP(sw, r)
		log.Printf("method=%s status=%d path=%s duration=%s",
			r.Method, sw.status, r.URL.RequestURI(), time.Since(start))
	})
}
