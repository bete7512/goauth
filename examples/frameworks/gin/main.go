package main

import (
	"log"
	"net/http"
	"time"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/gin-gonic/gin"
)

func main() {
	// Create auth configuration
	conf := config.Config{
		App: config.AppConfig{
			BasePath:    "/api",
			Domain:      "localhost",
			FrontendURL: "http://localhost:3000",
			Swagger: config.SwaggerConfig{
				Enable:      true,
				Title:       "GoAuth API",
				Version:     "1.0.0",
				Description: "Authentication API with Gin",
				DocPath:     "/docs",
				Host:        "localhost:8080",
			},
		},
		Database: config.DatabaseConfig{
			// Choose your database type:
			// Type: config.PostgreSQL, // For PostgreSQL
			// Type: config.MySQL,      // For MySQL
			// Type: config.MariaDB,    // For MariaDB
			// Type: config.SQLite,     // For SQLite
			// Type: config.MongoDB,    // For MongoDB
			Type:        config.SQLite,                          // Using SQLite for this example
			URL:         "file:goauth.db?cache=shared&_fk=true", // SQLite file
			AutoMigrate: true,
		},
		Security: config.SecurityConfig{
			RateLimiter: config.RateLimiterConfig{
				Enabled: true,
				Type:    "memory",
				Routes: map[string]config.LimiterConfig{
					"login": {
						WindowSize:    60 * time.Second,
						MaxRequests:   5,
						BlockDuration: 60 * time.Second,
					},
					"register": {
						WindowSize:    300 * time.Second,
						MaxRequests:   3,
						BlockDuration: 300 * time.Second,
					},
				},
			},
			Recaptcha: config.RecaptchaConfig{
				Enabled:   false,
				SecretKey: "",
				SiteKey:   "",
				Provider:  "google",
				Routes: map[string]bool{
					"login":    false,
					"register": false,
				},
			},
		},
		AuthConfig: config.AuthConfig{
			JWT: config.JWTConfig{
				Secret:             "your-secret-key-here",
				AccessTokenTTL:     3600,  // 1 hour
				RefreshTokenTTL:    86400, // 24 hours
				EnableCustomClaims: false,
			},
			Tokens: config.TokenConfig{
				HashSaltLength:       16,
				PhoneVerificationTTL: 600,  // 10 minutes
				EmailVerificationTTL: 3600, // 1 hour
				PasswordResetTTL:     600,  // 10 minutes
				TwoFactorTTL:         600,  // 10 minutes
				MagicLinkTTL:         600,  // 10 minutes
			},
			Methods: config.AuthMethodsConfig{
				Type:               "email",
				EnableTwoFactor:    false,
				EnableMultiSession: false,
				EnableMagicLink:    false,
				TwoFactorMethod:    "",
				EmailVerification: config.EmailVerificationConfig{
					EnableOnSignup:   false,
					VerificationURL:  "http://localhost:3000/verify",
					SendWelcomeEmail: false,
				},
				PhoneVerification: config.PhoneVerificationConfig{
					EnableOnSignup:      false,
					UniquePhoneNumber:   false,
					PhoneColumnRequired: false,
					PhoneRequired:       false,
				},
			},
			PasswordPolicy: config.PasswordPolicy{
				HashSaltLength: 16,
				MinLength:      8,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumber:  true,
				RequireSpecial: false,
			},
			Cookie: config.CookieConfig{
				Name:     "auth_token",
				Secure:   false,
				HttpOnly: true,
				Domain:   "",
				Path:     "/",
				MaxAge:   86400,
				SameSite: 1,
			},
		},
		Email: config.EmailConfig{
			SenderType: config.CustomEmailSender,
			Branding: config.BrandingConfig{
				LogoURL:      "",
				CompanyName:  "GoAuth",
				PrimaryColor: "#007bff",
			},
		},
		SMS: config.SMSConfig{
			Branding: config.BrandingConfig{
				CompanyName: "GoAuth",
			},
			CustomSender: nil,
		},
		Providers: config.ProvidersConfig{
			Enabled: []config.AuthProvider{},
		},
	}

	// Initialize auth
	authInstance, err := auth.NewBuilder().
		WithConfig(conf).
		Build()
	if err != nil {
		log.Fatal("Failed to initialize auth:", err)
	}

	// Create Gin router
	router := gin.Default()

	// Add CORS middleware
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

	// Register auth routes manually
	authRoutes := authInstance.GetRoutes()
	for _, route := range authRoutes {
		handler := authInstance.GetWrappedHandler(route)
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

	// Add a protected route example
	protected := router.Group("/protected")
	// Note: You would need to implement a Gin-specific auth middleware
	// For now, we'll add a simple example
	{
		protected.GET("/me", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "Protected route accessed successfully",
				"note":    "Implement proper auth middleware for Gin",
			})
		})
	}

	// Add a public route
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"message": "GoAuth API is running",
		})
	})

	// Start server
	log.Println("Server starting on :8080")
	log.Println("API Documentation available at: http://localhost:8080/api/docs")
	log.Fatal(router.Run(":8080"))
}
