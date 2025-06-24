// Package core - Clean HTTP-only authentication library
package api

import (
	"net/http"
	"strings"

	"github.com/bete7512/goauth/api/docs"
	middleware "github.com/bete7512/goauth/api/middlewares"
	"github.com/bete7512/goauth/api/routes"
	oauthRoutes "github.com/bete7512/goauth/api/routes/oauth"
	"github.com/bete7512/goauth/config"
)

// AuthService is the main authentication service
type AuthService struct {
	Config   *config.Config
	Auth     *config.Auth
	handlers *routes.AuthHandler
	mux      *http.ServeMux
}

// NewAuthService creates a new authentication service
func NewAuthService(cfg *config.Config, auth *config.Auth) *AuthService {
	service := &AuthService{
		Config:   cfg,
		Auth:     auth,
		handlers: &routes.AuthHandler{Auth: auth},
		mux:      http.NewServeMux(),
	}

	service.setupRoutes()
	return service
}

// ServeHTTP implements http.Handler interface - this is your main entry point
func (a *AuthService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

// GetAuthMiddleware returns standard HTTP middleware for protecting routes
func (a *AuthService) GetAuthMiddleware() func(http.Handler) http.Handler {
	middlewareHandler := middleware.NewMiddleware(a.Auth)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use your existing auth middleware logic
			wrappedHandler := middlewareHandler.AuthMiddleware(next.ServeHTTP)
			wrappedHandler(w, r)
		})
	}
}

// GetRateLimitMiddleware returns rate limiting middleware
func (a *AuthService) GetRateLimitMiddleware(routeName string) func(http.Handler) http.Handler {
	if !a.Auth.Config.Features.EnableRateLimiter {
		return func(next http.Handler) http.Handler { return next }
	}

	middlewareHandler := middleware.NewMiddleware(a.Auth)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this route needs rate limiting
			if _, needsRateLimit := a.Auth.Config.Security.RateLimiter.Routes[routeName]; needsRateLimit {
				wrappedHandler := middlewareHandler.RateLimiterMiddleware(*a.Auth.RateLimiter, &a.Auth.Config.Security.RateLimiter, routeName, next.ServeHTTP)
				wrappedHandler(w, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// GetHookMiddleware returns middleware that executes hooks
func (a *AuthService) GetHookMiddleware(routeName string) func(http.Handler) http.Handler {
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

			// Execute after hooks
			if a.Auth.HookManager != nil {
				a.Auth.HookManager.ExecuteAfterHooks(routeName, w, r)
			}
		})
	}
}

// setupRoutes configures all authentication routes
func (a *AuthService) setupRoutes() {
	basePath := a.Config.App.BasePath
	if basePath == "" {
		basePath = ""
	}

	// Core authentication routes
	a.addRoute("POST", basePath+"/register", config.RouteRegister, a.handlers.HandleRegister)
	a.addRoute("POST", basePath+"/login", config.RouteLogin, a.handlers.HandleLogin)
	a.addRoute("POST", basePath+"/refresh-token", config.RouteRefreshToken, a.handlers.HandleRefreshToken)
	a.addRoute("POST", basePath+"/forgot-password", config.RouteForgotPassword, a.handlers.HandleForgotPassword)
	a.addRoute("POST", basePath+"/reset-password", config.RouteResetPassword, a.handlers.HandleResetPassword)

	// Magic link routes
	a.addRoute("POST", basePath+"/send-magic-link", config.RouteSendMagicLink, a.handlers.SendMagicLink)
	a.addRoute("POST", basePath+"/verify-magic-link", config.RouteVerifyMagicLink, a.handlers.HandleVerifyMagicLink)

	// Verification routes
	a.addRoute("POST", basePath+"/verification/email/send", config.RouteSendEmailVerification, a.handlers.HandleSendEmailVerification)
	a.addRoute("POST", basePath+"/verification/email/verify", config.RouteVerifyEmail, a.handlers.HandleVerifyEmail)
	a.addRoute("POST", basePath+"/verification/phone/send", config.RouteSendPhoneVerification, a.handlers.HandleSendPhoneVerification)
	a.addRoute("POST", basePath+"/verification/phone/verify", config.RouteVerifyPhone, a.handlers.HandleVerifyPhone)

	// Protected routes (require authentication)
	a.addProtectedRoute("GET", basePath+"/me", config.RouteGetMe, a.handlers.HandleGetUser)
	a.addProtectedRoute("POST", basePath+"/update-profile", config.RouteUpdateProfile, a.handlers.HandleUpdateProfile)
	a.addProtectedRoute("POST", basePath+"/logout", config.RouteLogout, a.handlers.HandleLogout)
	a.addProtectedRoute("POST", basePath+"/deactivate-user", config.RouteDeactivateUser, a.handlers.HandleDeactivateUser)

	// Two-factor authentication routes
	a.addProtectedRoute("POST", basePath+"/enable-two-factor", config.RouteEnableTwoFactor, a.handlers.HandleEnableTwoFactor)
	a.addProtectedRoute("POST", basePath+"/verify-two-factor", config.RouteVerifyTwoFactor, a.handlers.HandleVerifyTwoFactor)
	a.addProtectedRoute("POST", basePath+"/disable-two-factor", config.RouteDisableTwoFactor, a.handlers.HandleDisableTwoFactor)

	// Admin routes
	// a.adminRoutes("GET", basePath+"/admin/users", config.RouteGetUsers, a.handlers.HandleGetUsers)
	// a.adminRoutes("POST", basePath+"/admin/users", config.RouteCreateUser, a.handlers.HandleCreateUser)
	// a.adminRoutes("PUT", basePath+"/admin/users/{id}", config.RouteUpdateUser, a.handlers.HandleUpdateUser)
	// a.adminRoutes("DELETE", basePath+"/admin/users/{id}", config.RouteDeleteUser, a.handlers.HandleDeleteUser)

	// OAuth routes
	a.setupOAuthRoutes(basePath)
}

// addRoute adds a route with middleware chain
func (a *AuthService) addRoute(method, path, routeName string, handler http.HandlerFunc) {
	finalHandler := a.buildMiddlewareChain(routeName, handler)
	a.mux.HandleFunc(method+" "+path, finalHandler)
}

// addProtectedRoute adds a route that requires authentication
func (a *AuthService) addProtectedRoute(method, path, routeName string, handler http.HandlerFunc) {
	middlewareHandler := middleware.NewMiddleware(a.Auth)

	// Wrap with auth middleware first
	authHandler := middlewareHandler.AuthMiddleware(handler)

	// Then build the rest of the middleware chain
	finalHandler := a.buildMiddlewareChain(routeName, authHandler)
	a.mux.HandleFunc(method+" "+path, finalHandler)
}

func (a *AuthService) adminRoutes(method, path, routeName string, handler http.HandlerFunc) {
	middlewareHandler := middleware.NewMiddleware(a.Auth)
	authHandler := middlewareHandler.AuthMiddleware(handler)
	authHandler = middlewareHandler.AdminMiddleware(authHandler)
	finalHandler := a.buildMiddlewareChain(routeName, authHandler)
	a.mux.HandleFunc(method+" "+path, finalHandler)
}

// buildMiddlewareChain builds the middleware chain for a route
func (a *AuthService) buildMiddlewareChain(routeName string, handler http.HandlerFunc) http.HandlerFunc {
	// Start with the base handler
	var finalHandler http.Handler = http.HandlerFunc(handler)

	// Add hook middleware
	finalHandler = a.GetHookMiddleware(routeName)(finalHandler)

	// Add rate limiting if enabled
	finalHandler = a.GetRateLimitMiddleware(routeName)(finalHandler)

	return finalHandler.ServeHTTP
}

// setupOAuthRoutes configures OAuth provider routes
func (a *AuthService) setupOAuthRoutes(basePath string) {
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
			a.Auth.Logger.Warnf("OAuth provider %s is configured but not supported, skipping.", providerName)
			continue
		}

		a.mux.HandleFunc("GET "+providerPath, provider.SignIn)
		a.mux.HandleFunc("GET "+providerPath+"/callback", provider.Callback)
	}
}

// Hook management methods
func (a *AuthService) RegisterBeforeHook(route string, hook func(http.ResponseWriter, *http.Request) (bool, error)) error {
	if a.Auth.HookManager == nil {
		return nil
	}
	return a.Auth.HookManager.RegisterBeforeHook(route, hook)
}

func (a *AuthService) RegisterAfterHook(route string, hook func(http.ResponseWriter, *http.Request) (bool, error)) error {
	if a.Auth.HookManager == nil {
		return nil
	}
	return a.Auth.HookManager.RegisterAfterHook(route, hook)
}

// RouteInfo represents a single route with its metadata
type RouteInfo struct {
	Method       string
	Path         string
	Name         string
	Handler      http.HandlerFunc
	RequiresAuth bool
}

// GetRoutes returns all routes for manual registration
func (a *AuthService) GetRoutes() []RouteInfo {
	basePath := a.Config.App.BasePath
	if basePath == "" {
		basePath = ""
	}

	routes := []RouteInfo{
		// Public routes
		{Method: "POST", Path: basePath + "/register", Name: config.RouteRegister, Handler: a.handlers.HandleRegister, RequiresAuth: false},
		{Method: "POST", Path: basePath + "/login", Name: config.RouteLogin, Handler: a.handlers.HandleLogin, RequiresAuth: false},
		{Method: "POST", Path: basePath + "/refresh-token", Name: config.RouteRefreshToken, Handler: a.handlers.HandleRefreshToken, RequiresAuth: false},
		{Method: "POST", Path: basePath + "/forgot-password", Name: config.RouteForgotPassword, Handler: a.handlers.HandleForgotPassword, RequiresAuth: false},
		{Method: "POST", Path: basePath + "/reset-password", Name: config.RouteResetPassword, Handler: a.handlers.HandleResetPassword, RequiresAuth: false},
		{Method: "POST", Path: basePath + "/send-magic-link", Name: config.RouteSendMagicLink, Handler: a.handlers.SendMagicLink, RequiresAuth: false},
		{Method: "POST", Path: basePath + "/verify-magic-link", Name: config.RouteVerifyMagicLink, Handler: a.handlers.HandleVerifyMagicLink, RequiresAuth: false},
		{Method: "POST", Path: basePath + "/verification/email/send", Name: config.RouteSendEmailVerification, Handler: a.handlers.HandleSendEmailVerification, RequiresAuth: false},
		{Method: "POST", Path: basePath + "/verification/email/verify", Name: config.RouteVerifyEmail, Handler: a.handlers.HandleVerifyEmail, RequiresAuth: false},
		{Method: "POST", Path: basePath + "/verification/phone/send", Name: config.RouteSendPhoneVerification, Handler: a.handlers.HandleSendPhoneVerification, RequiresAuth: false},
		{Method: "POST", Path: basePath + "/verification/phone/verify", Name: config.RouteVerifyPhone, Handler: a.handlers.HandleVerifyPhone, RequiresAuth: false},

		// Protected routes
		{Method: "GET", Path: basePath + "/me", Name: config.RouteGetMe, Handler: a.handlers.HandleGetUser, RequiresAuth: true},
		{Method: "POST", Path: basePath + "/update-profile", Name: config.RouteUpdateProfile, Handler: a.handlers.HandleUpdateProfile, RequiresAuth: true},
		{Method: "POST", Path: basePath + "/logout", Name: config.RouteLogout, Handler: a.handlers.HandleLogout, RequiresAuth: true},
		{Method: "POST", Path: basePath + "/deactivate-user", Name: config.RouteDeactivateUser, Handler: a.handlers.HandleDeactivateUser, RequiresAuth: true},
		{Method: "POST", Path: basePath + "/enable-two-factor", Name: config.RouteEnableTwoFactor, Handler: a.handlers.HandleEnableTwoFactor, RequiresAuth: true},
		{Method: "POST", Path: basePath + "/verify-two-factor", Name: config.RouteVerifyTwoFactor, Handler: a.handlers.HandleVerifyTwoFactor, RequiresAuth: true},
		{Method: "POST", Path: basePath + "/disable-two-factor", Name: config.RouteDisableTwoFactor, Handler: a.handlers.HandleDisableTwoFactor, RequiresAuth: true},
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
			RouteInfo{Method: "GET", Path: providerPath, Name: "oauth." + string(providerName) + ".signin", Handler: provider.SignIn, RequiresAuth: false},
			RouteInfo{Method: "GET", Path: providerPath + "/callback", Name: "oauth." + string(providerName) + ".callback", Handler: provider.Callback, RequiresAuth: false},
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
func (a *AuthService) getSwaggerRoutes(basePath string) []RouteInfo {
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
		{Method: "GET", Path: basePath + "/" + docPath + "/", Name: "swagger.ui", Handler: mainHandler, RequiresAuth: false},
		{Method: "GET", Path: basePath + "/" + docPath, Name: "swagger.ui.redirect", Handler: mainHandler, RequiresAuth: false},

		// JSON spec route - this serves the OpenAPI JSON specification
		{Method: "GET", Path: basePath + "/" + docPath + "/swagger.json", Name: "swagger.json", Handler: jsonHandler, RequiresAuth: false},
		{Method: "GET", Path: basePath + "/swagger.json", Name: "swagger.json.alt", Handler: jsonHandler, RequiresAuth: false},
	}
}

// GetWrappedHandler returns a handler with all middleware applied
func (a *AuthService) GetWrappedHandler(routeInfo RouteInfo) http.HandlerFunc {
	handler := routeInfo.Handler

	// Apply auth middleware if required
	if routeInfo.RequiresAuth {
		middlewareHandler := middleware.NewMiddleware(a.Auth)
		handler = middlewareHandler.AuthMiddleware(handler)
	}
	// Apply admin middleware if required
	// TODO: Implement admin middleware
	// if routeInfo.RequiresAdmin {
	// 	middlewareHandler := middleware.NewMiddleware(a.Auth)
	// 	handler = middlewareHandler.AdminMiddleware(handler)
	// }
	// Build middleware chain
	return a.buildMiddlewareChain(routeInfo.Name, handler)
}
