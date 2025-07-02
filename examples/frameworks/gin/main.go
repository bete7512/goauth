package main

import (
	"log"
	"time"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/gin-gonic/gin"
)

func main() {
	// Create configuration
	config := createConfig()

	// Initialize GoAuth using the builder pattern
	authService, err := auth.NewBuilder().WithConfig(config).Build()
	if err != nil {
		log.Fatal(err)
	}

	// Setup Gin router
	router := gin.Default()

	// Register auth routes manually
	authRoutes := authService.GetRoutes()
	for _, route := range authRoutes {
		handler := authService.GetWrappedHandler(route)
		ginHandler := gin.WrapF(handler)

		switch route.Method {
		case "GET":
			router.GET(route.Path, ginHandler)
		case "POST":
			router.POST(route.Path, ginHandler)
		case "PUT":
			router.PUT(route.Path, ginHandler)
		case "DELETE":
			router.DELETE(route.Path, ginHandler)
		}
	}

	// Add a simple health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "OK"})
	})

	log.Println("Gin server starting on :8080")
	router.Run(":8080")
}

func createConfig() config.Config {
	return config.Config{
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
}
