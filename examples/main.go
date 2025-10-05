package main

import (
	"context"
	"log"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/csrf"
	"github.com/bete7512/goauth/internal/modules/magiclink"
	"github.com/bete7512/goauth/internal/modules/notification"
	"github.com/bete7512/goauth/internal/modules/notification/services"
	"github.com/bete7512/goauth/internal/modules/notification/services/senders"
	"github.com/bete7512/goauth/internal/storage"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
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
		Security: config.SecurityConfig{
			JwtSecretKey:  "your-secret-key-change-in-production",
			EncryptionKey: "your-encryption-key-change-in-production",
		},
		AutoMigrate: true,
		SwaggerConfig: &config.SwaggerConfig{
			Title:       "GoAuth Docs",
			Description: "GoAuth Documentation",
			Version:     "1.0.0",
			Servers: []config.SwaggerServer{
				{URL: "http://localhost:8080", Description: "Development Server"},
				{URL: "https://goauth.com", Description: "Production Server"},
			},
		},
	})
	if err != nil {
		log.Fatalf("Failed to create auth: %v", err)
	}

	// Register modules before Initialize
	// authInstance.Use(core.New(&core.Config{}))
	authInstance.Use(magiclink.New())
	// authInstance.Use(twofactor.New(&twofactor.TwoFactorConfig{
	// 	Issuer:           "MyAwesomeApp",
	// 	Required:         false,
	// 	BackupCodesCount: 10,
	// 	CodeLength:       8,
	// }))
	authInstance.Use(notification.New(&notification.Config{
		EmailSender: senders.NewSendGridEmailSender(&senders.SendGridConfig{
			APIKey:          "your-sendgrid-api-key",
			DefaultFrom:     "noreply@yourapp.com",
			DefaultFromName: "Your App",
		}),
		ServiceConfig: &services.NotificationConfig{
			AppName:           "Your App",
			SupportEmail:      "support@yourapp.com",
			SupportLink:       "https://yourapp.com/support",
			EnableEmailAlerts: true,
		},
		EnableWelcomeEmail:        true,
		EnablePasswordResetEmail:  true,
		EnablePasswordResetSMS:    false,
		EnableLoginAlerts:         false,
		EnablePasswordChangeAlert: true,
		Enable2FANotifications:    true,
	}))
	// authInstance.Use(ratelimiter.New(&ratelimiter.RateLimiterConfig{
	// 	RequestsPerMinute: 60,
	// 	RequestsPerHour:   1000,
	// 	BurstSize:         10,
	// }))
	csrfModule := csrf.New(&csrf.CSRFConfig{
		TokenLength:      32,
		TokenExpiry:      3600,
		CookieName:       "csrf_token",
		HeaderName:       "X-CSRF-Token",
		FormFieldName:    "csrf_token",
		Secure:           true,
		HTTPOnly:         true,
		SameSite:         http.SameSiteStrictMode,
		OnlyToPaths:      []string{"/auth/login", "/auth/signup", "/auth/forgot-password"},
		ProtectedMethods: []string{"POST", "PUT", "DELETE"},
	})
	authInstance.Use(csrfModule)

	// Initialize after all modules are registered
	if err := authInstance.Initialize(context.Background()); err != nil {
		log.Fatalf("Failed to initialize auth: %v", err)
	}

	// Enable swagger after initialization
	if err := authInstance.EnableSwagger(); err != nil {
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
