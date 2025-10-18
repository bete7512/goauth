package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/modules/notification"
	"github.com/bete7512/goauth/internal/modules/notification/services"
	"github.com/bete7512/goauth/internal/modules/notification/services/senders"
	"github.com/bete7512/goauth/internal/storage"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
)

func main() {
	// Create storage instance using factory
	// Option 1: Use built-in GORM storage
	store, err := storage.NewStorage(config.StorageConfig{
		Driver:       "gorm",
		Dialect:      "postgres",
		DSN:          "host=localhost user=postgres password=password dbname=authdb1 port=5432 sslmode=disable",
		AutoMigrate:  true,
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
			URL:                "http://localhost:3000",
			Domain:             "localhost",
			ResetPasswordPath:  "/reset-password",
			VerifyEmailCallbackPath:    "/verify-email",
			LoginPath:          "/login",
			SignupPath:         "/signup",
			LogoutPath:         "/logout",
			ProfilePath:        "/profile",
			ChangePasswordPath: "/change-password",
		},
	})
	if err != nil {
		log.Fatalf("Failed to create auth: %v", err)
	}

	// Configure notification module with email verification support
	authInstance.Use(notification.New(&notification.Config{
		EmailSender: senders.NewSendGridEmailSender(&senders.SendGridConfig{
			APIKey:          "your-sendgrid-api-key",
			DefaultFrom:     "noreply@yourapp.com",
			DefaultFromName: "Your App",
		}),
		ServiceConfig: &services.NotificationConfig{
			AppName:      "Your App",
			SupportEmail: "support@yourapp.com",
			SupportLink:  "http://localhost:3000/support",
		},
		// Enable various notification types
		EnableWelcomeEmail:        true,  // Send welcome email after signup (if no verification required)
		EnablePasswordResetEmail:  true,  // Send password reset emails
		EnablePasswordResetSMS:    false, // SMS for password reset (requires SMS sender)
		EnableLoginAlerts:         true,  // Send login alerts (security feature)
		EnablePasswordChangeAlert: true,  // Alert on password changes
		Enable2FANotifications:    true,  // Send 2FA codes (requires phone verification)
	}))

	// Register custom hooks (user-defined)
	authInstance.On(types.EventBeforeSignup, func(ctx context.Context, e *types.Event) error {
		log.Println("looooooooooooooooooooooooooo Handler error for before:signup", e.Type, e.Data)
		time.Sleep(30 * time.Second)	
		log.Println("looooooooooooooooooooooooooo Handler error for before:signup", e.Type)
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
			Path:        "/docs/v1",
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
			mux.Handle(route.Path, route.Handler)
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

func fiberHandler(auth *auth.Auth) *fiber.App {
	fiber := fiber.New()
	for _, route := range auth.Routes() {
		switch route.Method {
		case http.MethodGet:
			fiber.Get(route.Path, adaptor.HTTPHandler(route.Handler))
		case http.MethodPost:
			fiber.Post(route.Path, adaptor.HTTPHandler(route.Handler))
		case http.MethodPut:
			fiber.Put(route.Path, adaptor.HTTPHandler(route.Handler))
		case http.MethodDelete:
			fiber.Delete(route.Path, adaptor.HTTPHandler(route.Handler))
		case http.MethodPatch:
			fiber.Patch(route.Path, adaptor.HTTPHandler(route.Handler))
		case http.MethodOptions:
			fiber.Options(route.Path, adaptor.HTTPHandler(route.Handler))
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
		switch route.Method {
		case http.MethodGet:
			r.GET(route.Path, gin.WrapF(route.Handler))
		case http.MethodPost:
			r.POST(route.Path, gin.WrapF(route.Handler))
		case http.MethodPut:
			r.PUT(route.Path, gin.WrapF(route.Handler))
		case http.MethodDelete:
			r.DELETE(route.Path, gin.WrapF(route.Handler))
		case http.MethodPatch:
			r.PATCH(route.Path, gin.WrapF(route.Handler))
		case http.MethodOptions:
			r.OPTIONS(route.Path, gin.WrapF(route.Handler))
		}
	}
	r.Run(":8080")
	return r
}
