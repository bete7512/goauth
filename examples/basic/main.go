package main

import (
	"log"
	"net/http"
	"time"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
)

func main() {
	// Create configuration
	config := config.Config{
		App: config.AppConfig{
			BasePath:    "/auth",
			Domain:      "localhost",
			FrontendURL: "http://localhost:3000",
		},
		Database: config.DatabaseConfig{
			Type: "postgres",
			URL:  "postgres://user:pass@localhost/dbname?sslmode=disable",
		},
		AuthConfig: config.AuthConfig{
			JWT: config.JWTConfig{
				Secret:             "your-secret-key-32-chars-long",
				AccessTokenTTL:     15 * time.Minute,
				RefreshTokenTTL:    7 * 24 * time.Hour,
				EnableCustomClaims: false,
			},
			Tokens: config.TokenConfig{
				HashSaltLength:       16,
				PhoneVerificationTTL: 10 * time.Minute,
				EmailVerificationTTL: 1 * time.Hour,
				PasswordResetTTL:     10 * time.Minute,
				TwoFactorTTL:         10 * time.Minute,
				MagicLinkTTL:         10 * time.Minute,
			},
			Methods: config.AuthMethodsConfig{
				Type:                  config.AuthenticationTypeCookie,
				EnableTwoFactor:       true,
				EnableMultiSession:    false,
				EnableMagicLink:       false,
				EnableSmsVerification: false,
				TwoFactorMethod:       "email",
				EmailVerification: config.EmailVerificationConfig{
					EnableOnSignup:   true,
					VerificationURL:  "http://localhost:3000/verify",
					SendWelcomeEmail: false,
				},
			},
			PasswordPolicy: config.PasswordPolicy{
				HashSaltLength: 16,
				MinLength:      8,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumber:  true,
				RequireSpecial: true,
			},
			Cookie: config.CookieConfig{
				Name:     "auth_token",
				Path:     "/",
				MaxAge:   86400,
				Secure:   false,
				HttpOnly: true,
				SameSite: 1,
			},
		},
		Features: config.FeaturesConfig{
			EnableRateLimiter:   false,
			EnableRecaptcha:     false,
			EnableCustomJWT:     false,
			EnableCustomStorage: false,
		},
		Security: config.SecurityConfig{
			RateLimiter: config.RateLimiterConfig{
				Enabled: false,
				Type:    config.MemoryRateLimiter,
				Routes:  make(map[string]config.LimiterConfig),
			},
			Recaptcha: config.RecaptchaConfig{
				Enabled:   false,
				SecretKey: "",
				SiteKey:   "",
				Provider:  "google",
				APIURL:    "",
				Routes:    make(map[string]bool),
			},
		},
		Email: config.EmailConfig{
			Sender: config.EmailSenderConfig{
				Type:         "sendgrid",
				FromEmail:    "noreply@example.com",
				FromName:     "My App",
				SupportEmail: "support@example.com",
				CustomSender: nil,
			},
		},
		SMS: config.SMSConfig{
			CompanyName:  "My App",
			CustomSender: nil,
		},
		Providers: config.ProvidersConfig{
			Enabled: []config.AuthProvider{},
		},
	}

	// Initialize GoAuth using the builder pattern
	authService, err := auth.NewBuilder().WithConfig(config).Build()
	if err != nil {
		log.Fatal(err)
	}

	// Setup HTTP server
	mux := http.NewServeMux()

	// Register auth routes manually
	authRoutes := authService.GetRoutes()
	for _, route := range authRoutes {
		handler := authService.GetWrappedHandler(route)
		mux.HandleFunc(route.Method+" "+route.Path, handler)
	}

	// Add a simple health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
