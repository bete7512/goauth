package main

import (
	"context"
	"net/http"

	"github.com/bete7512/goauth/modules/csrf"
	"github.com/bete7512/goauth/modules/magiclink"
	"github.com/bete7512/goauth/modules/ratelimiter"
	"github.com/bete7512/goauth/modules/twofactor"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
)

func main() {
	// Application code here
	auth, err := auth.New(
		&config.Config{
			// Configuration fields here
		},
	)
	if err != nil {
		// Handle error
	}

	if err := auth.Initialize(context.Background()); err != nil {
		// Handle error
	}
	auth.Use(magiclink.New())
	auth.Use(ratelimiter.New(
		&ratelimiter.RateLimiterConfig{
			RequestsPerMinute: 60,
			RequestsPerHour:   1000,
			BurstSize:         10,
		},
	))
	auth.Use(csrf.New(
		&csrf.CSRFConfig{
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
		},
	))
	auth.Use(twofactor.New(
		&twofactor.TwoFactorConfig{
			Issuer:           "GoAuth",
			Required:         true,
			BackupCodesCount: 10,
			CodeLength:       8,
			Options:          &twofactor.TwoFactorOptions{
		},
	))
	// auth.Use(oauth.New())
	server := "http"
	switch server {
	case "http":
		mux := http.NewServeMux()
		for _, route := range auth.Routes() {
			mux.Handle(route.Path, route.Handler)
		}
		http.ListenAndServe(":8080", mux)
	case "fiber":
		fiberHandler(auth)
	case "chi":
		chiHandler(auth)
	case "gin":
		ginHandler(auth)
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

func chiHandler(auth *auth.Auth) chi.Mux {
	chi := chi.NewRouter()
	for _, route := range auth.Routes() {
		switch route.Method {
		case http.MethodGet:
			chi.Get(route.Path, route.Handler)
		case http.MethodPost:
			chi.Post(route.Path, route.Handler)
		case http.MethodPut:
			chi.Put(route.Path, route.Handler)
		case http.MethodDelete:
			chi.Delete(route.Path, route.Handler)
		case http.MethodPatch:
			chi.Patch(route.Path, route.Handler)
		case http.MethodOptions:
			chi.Options(route.Path, route.Handler)
		}
	}
	chi.Use(auth.RequireAuth)
	chi.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, World!"))
	})
	mux := http.NewServeMux()
	mux.Handle("/", chi)
	return chi
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
	return r
}
