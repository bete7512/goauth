// Package core - Clean HTTP-only authentication library
package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/api/docs"
	"github.com/bete7512/goauth/internal/api/handlers"
	middleware "github.com/bete7512/goauth/internal/api/middlewares"
	oauthRoutes "github.com/bete7512/goauth/internal/api/handlers/oauth"
	"github.com/bete7512/goauth/pkg/config"
)

// AuthHandler is the main authentication service
type AuthHandler struct {
	Auth       *config.Auth
	handlers   *handlers.AuthRoutes
	middleware *middleware.Middleware
}

// NewAuthHandler creates a new authentication service
func NewAuthHandler(auth *config.Auth) *AuthHandler {
	routes := handlers.NewAuthRoutes(auth)
	middleware := middleware.NewMiddleware(auth)
	service := &AuthHandler{
		Auth:       auth,
		handlers:   routes,
		middleware: middleware,
	}
	return service
}

// GetAuthMiddleware returns standard HTTP middleware for protecting routes
func (a *AuthHandler) GetAuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrappedHandler := a.middleware.AuthMiddleware(next.ServeHTTP)
			wrappedHandler(w, r)
		})
	}
}

// GetRateLimitMiddleware returns rate limiting middleware
func (a *AuthHandler) GetRateLimitMiddleware(routeName string) func(http.Handler) http.Handler {
	if !a.Auth.Config.Features.EnableRateLimiter {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this route needs rate limiting
			if _, needsRateLimit := a.Auth.Config.Security.RateLimiter.Routes[routeName]; needsRateLimit {
				wrappedHandler := a.middleware.RateLimiterMiddleware(a.Auth.RateLimiter, &a.Auth.Config.Security.RateLimiter, routeName, next.ServeHTTP)
				wrappedHandler(w, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// GetHookMiddleware returns middleware that executes hooks
func (a *AuthHandler) GetHookMiddleware(routeName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Execute before hooks
			if a.Auth.HookManager != nil {
				if !a.Auth.HookManager.ExecuteBeforeHooks(routeName, w, r) {
					return // Hook handled the response
				}
			}

			// Execute main handler
			next.ServeHTTP(w, r)

		})
	}
}

// buildMiddlewareChain builds the middleware chain for a route
func (a *AuthHandler) buildMiddlewareChain(routeName string, handler http.HandlerFunc) http.HandlerFunc {
	// Start with the base handler
	var finalHandler http.Handler = http.HandlerFunc(handler)

	// Add hook middleware
	finalHandler = a.GetHookMiddleware(routeName)(finalHandler)

	// Add rate limiting if enabled
	finalHandler = a.GetRateLimitMiddleware(routeName)(finalHandler)

	return finalHandler.ServeHTTP
}

// Hook management methods
func (a *AuthHandler) RegisterBeforeHook(route string, hook func(http.ResponseWriter, *http.Request) (bool, error)) error {
	if a.Auth.HookManager == nil {
		return errors.New("hook manager is nil")
	}
	return a.Auth.HookManager.RegisterBeforeHook(route, hook)
}

func (a *AuthHandler) RegisterAfterHook(route string, hook func(http.ResponseWriter, *http.Request) (bool, error)) error {
	if a.Auth.HookManager == nil {
		return errors.New("hook manager is nil")
	}
	return a.Auth.HookManager.RegisterAfterHook(route, hook)
}

// RouteInfo represents a single route with its metadata
type RouteInfo struct {
	Method  string
	Path    string
	Name    string
	Handler http.HandlerFunc
}

// GetRoutes returns all routes for manual registration
func (a *AuthHandler) GetRoutes() []RouteInfo {
	basePath := a.Auth.Config.App.BasePath
	if basePath == "" {
		basePath = ""
	}

	routes := []RouteInfo{
		// Public routes
		{Method: "POST", Path: basePath + "/register", Name: config.RouteRegister, Handler: a.handlers.HandleRegister},
		{Method: "POST", Path: basePath + "/login", Name: config.RouteLogin, Handler: a.handlers.HandleLogin},
		{Method: "POST", Path: basePath + "/refresh-token", Name: config.RouteRefreshToken, Handler: a.handlers.HandleRefreshToken},
		{Method: "POST", Path: basePath + "/forgot-password", Name: config.RouteForgotPassword, Handler: a.handlers.HandleForgotPassword},
		{Method: "POST", Path: basePath + "/reset-password", Name: config.RouteResetPassword, Handler: a.handlers.HandleResetPassword},
		{Method: "POST", Path: basePath + "/send-magic-link", Name: config.RouteSendMagicLink, Handler: a.handlers.SendMagicLink},
		{Method: "POST", Path: basePath + "/verify-magic-link", Name: config.RouteVerifyMagicLink, Handler: a.handlers.HandleVerifyMagicLink},
		{Method: "POST", Path: basePath + "/verification/email/send", Name: config.RouteSendEmailVerification, Handler: a.handlers.HandleSendEmailVerification},
		{Method: "POST", Path: basePath + "/verification/email/verify", Name: config.RouteVerifyEmail, Handler: a.handlers.HandleVerifyEmail},
		{Method: "POST", Path: basePath + "/verification/phone/send", Name: config.RouteSendPhoneVerification, Handler: a.handlers.HandleSendPhoneVerification},
		{Method: "POST", Path: basePath + "/verification/phone/verify", Name: config.RouteVerifyPhone, Handler: a.handlers.HandleVerifyPhone},

		// Protected routes
		{Method: "GET", Path: basePath + "/me", Name: config.RouteGetMe, Handler: a.middleware.AuthMiddleware(a.handlers.HandleGetUser)},
		{Method: "POST", Path: basePath + "/update-profile", Name: config.RouteUpdateProfile, Handler: a.middleware.AuthMiddleware(a.handlers.HandleUpdateProfile)},
		{Method: "POST", Path: basePath + "/logout", Name: config.RouteLogout, Handler: a.middleware.AuthMiddleware(a.handlers.HandleLogout)},
		{Method: "POST", Path: basePath + "/deactivate-user", Name: config.RouteDeactivateUser, Handler: a.middleware.AuthMiddleware(a.handlers.HandleDeactivateUser)},
		{Method: "POST", Path: basePath + "/enable-two-factor", Name: config.RouteEnableTwoFactor, Handler: a.middleware.AuthMiddleware(a.handlers.HandleEnableTwoFactor)},
		{Method: "POST", Path: basePath + "/verify-two-factor", Name: config.RouteVerifyTwoFactor, Handler: a.middleware.AuthMiddleware(a.handlers.HandleVerifyTwoFactor)},
		{Method: "POST", Path: basePath + "/disable-two-factor", Name: config.RouteDisableTwoFactor, Handler: a.middleware.AuthMiddleware(a.handlers.HandleDisableTwoFactor)},
	}

	// Add OAuth routes
	for _, providerName := range a.Auth.Config.Providers.Enabled {
		providerPath := basePath + "/oauth/" + string(providerName)

		var provider interface {
			SignIn(w http.ResponseWriter, r *http.Request)
			Callback(w http.ResponseWriter, r *http.Request)
		}

		switch providerName {
		case config.Google:
			provider = oauthRoutes.NewGoogleOauth(a.Auth)
		case config.GitHub:
			provider = oauthRoutes.NewGitHubOauth(a.Auth)
		default:
			continue
		}

		routes = append(routes,
			RouteInfo{Method: "GET", Path: providerPath, Name: "oauth." + string(providerName) + ".signin", Handler: provider.SignIn},
			RouteInfo{Method: "GET", Path: providerPath + "/callback", Name: "oauth." + string(providerName) + ".callback", Handler: provider.Callback},
		)
	}

	// Add Swagger routes if enabled
	if a.Auth.Config.App.Swagger.Enable {
		swaggerRoutes := a.getSwaggerRoutes(basePath)
		routes = append(routes, swaggerRoutes...)
	}

	return routes
}

// getSwaggerRoutes returns swagger-related routes
func (a *AuthHandler) getSwaggerRoutes(basePath string) []RouteInfo {
	swaggerInfo := docs.SwaggerInfo{
		Title:       a.Auth.Config.App.Swagger.Title,
		Description: a.Auth.Config.App.Swagger.Description,
		Version:     a.Auth.Config.App.Swagger.Version,
		Host:        a.Auth.Config.App.Swagger.Host,
		BasePath:    basePath,
		DocPath:     a.Auth.Config.App.Swagger.DocPath,
		Schemes:     []string{"http", "https"},
	}

	// Create the swagger handler
	swaggerHandler := docs.NewSwaggerHandler(swaggerInfo)

	// Create handler functions that delegate to the swagger handler
	mainHandler := func(w http.ResponseWriter, r *http.Request) {
		swaggerHandler.ServeHTTP(w, r)
	}

	jsonHandler := func(w http.ResponseWriter, r *http.Request) {
		swaggerHandler.ServeHTTP(w, r)
	}

	docPath := strings.TrimPrefix(a.Auth.Config.App.Swagger.DocPath, "/")

	return []RouteInfo{
		// Main swagger UI route - this serves the HTML interface
		{Method: "GET", Path: basePath + "/" + docPath + "/", Name: "swagger.ui", Handler: mainHandler},
		{Method: "GET", Path: basePath + "/" + docPath, Name: "swagger.ui.redirect", Handler: mainHandler},

		// JSON spec route - this serves the OpenAPI JSON specification
		{Method: "GET", Path: basePath + "/" + docPath + "/swagger.json", Name: "swagger.json", Handler: jsonHandler},
		{Method: "GET", Path: basePath + "/swagger.json", Name: "swagger.json.alt", Handler: jsonHandler},
	}
}

// GetWrappedHandler returns a handler with all middleware applied
func (a *AuthHandler) GetWrappedHandler(routeInfo RouteInfo) http.HandlerFunc {
	handler := routeInfo.Handler
	// Build middleware chain
	return a.buildMiddlewareChain(routeInfo.Name, handler)
}
