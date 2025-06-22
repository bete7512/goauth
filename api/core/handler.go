package core

import (
	"net/http"

	middleware "github.com/bete7512/goauth/api/middlewares"
	"github.com/bete7512/goauth/api/routes"
	oauthRoutes "github.com/bete7512/goauth/api/routes/oauth"
	"github.com/bete7512/goauth/config"
)

// AuthHandler implements RouteRegistry and MiddlewareChain interfaces
type AuthHandler struct {
	Auth *config.Auth
}

// NewAuthHandler creates a new AuthHandler instance
func NewAuthHandler(auth *config.Auth) *AuthHandler {
	return &AuthHandler{Auth: auth}
}

// GetCoreRoutes returns all standard authentication routes
func (h *AuthHandler) GetCoreRoutes() []RouteDefinition {
	// Create a routes handler to access the route methods
	routesHandler := &routes.AuthHandler{
		Auth: &config.Auth{
			Config:           h.Auth.Config,
			Repository:       h.Auth.Repository,
			HookManager:      h.Auth.HookManager,
			RateLimiter:      h.Auth.RateLimiter,
			RecaptchaManager: h.Auth.RecaptchaManager,
			Logger:           h.Auth.Logger,
			TokenManager:     h.Auth.TokenManager,
		},
	}

	return []RouteDefinition{
		{Name: config.RouteRegister, Method: http.MethodPost, Path: "/register", Handler: routesHandler.HandleRegister},
		{Name: config.RouteLogin, Method: http.MethodPost, Path: "/login", Handler: routesHandler.HandleLogin},
		{Name: config.RouteMagicLink, Method: http.MethodPost, Path: "/send-magic-link", Handler: routesHandler.SendMagicLink},
		{Name: config.RouteMagicLinkLogin, Method: http.MethodPost, Path: "/verify-magic-login", Handler: routesHandler.HandleVerifyMagicLink},
		{Name: config.RouteLogout, Method: http.MethodPost, Path: "/logout", Handler: routesHandler.HandleLogout},
		{Name: config.RouteRefreshToken, Method: http.MethodPost, Path: "/refresh-token", Handler: routesHandler.HandleRefreshToken},
		{Name: config.RouteForgotPassword, Method: http.MethodPost, Path: "/forgot-password", Handler: routesHandler.HandleForgotPassword},
		{Name: config.RouteResetPassword, Method: http.MethodPost, Path: "/reset-password", Handler: routesHandler.HandleResetPassword},
		{Name: config.RouteUpdateProfile, Method: http.MethodPost, Path: "/update-profile", Handler: routesHandler.HandleUpdateProfile},
		{Name: config.RouteDeactivateUser, Method: http.MethodPost, Path: "/deactivate-user", Handler: routesHandler.HandleDeactivateUser},
		{Name: config.RouteGetMe, Method: http.MethodGet, Path: "/me", Handler: routesHandler.HandleGetUser},
		{Name: config.RouteEnableTwoFactor, Method: http.MethodPost, Path: "/enable-two-factor", Handler: routesHandler.HandleEnableTwoFactor},
		{Name: config.RouteVerifyTwoFactor, Method: http.MethodPost, Path: "/verify-two-factor", Handler: routesHandler.HandleVerifyTwoFactor},
		{Name: config.RouteDisableTwoFactor, Method: http.MethodPost, Path: "/disable-two-factor", Handler: routesHandler.HandleDisableTwoFactor},
		{Name: config.RouteVerifyEmail, Method: http.MethodPost, Path: "/verify-email", Handler: routesHandler.HandleVerifyEmail},
		// {Name: config.RouteResendVerificationEmail, Method: http.MethodPost, Path: "/resend-verification-email", Handler: routesHandler.HandleResendVerificationEmail},
	}
}

// GetOAuthRoutes returns all OAuth provider routes
func (h *AuthHandler) GetOAuthRoutes() []RouteDefinition {
	routes := []RouteDefinition{}
	for _, providerName := range h.Auth.Config.Providers.Enabled {
		var provider interface {
			SignIn(w http.ResponseWriter, r *http.Request)
			Callback(w http.ResponseWriter, r *http.Request)
		}
		var basePath string

		switch providerName {
		case "google":
			provider = oauthRoutes.NewGoogleOauth(h.Auth)
			basePath = "/oauth/google"
		case "github":
			provider = oauthRoutes.NewGitHubOauth(h.Auth)
			basePath = "/oauth/github"
		default:
			h.Auth.Logger.Warnf("OAuth provider %s is configured but not supported, skipping.", providerName)
			continue
		}

		routes = append(routes, RouteDefinition{
			Name:    "oauth." + string(providerName) + ".signin",
			Method:  http.MethodGet,
			Path:    basePath,
			Handler: provider.SignIn,
		})
		routes = append(routes, RouteDefinition{
			Name:    "oauth." + string(providerName) + ".callback",
			Method:  http.MethodGet,
			Path:    basePath + "/callback",
			Handler: provider.Callback,
		})
	}
	return routes
}

// GetAllRoutes returns all routes (core + OAuth)
func (h *AuthHandler) GetAllRoutes() []RouteDefinition {
	return append(h.GetCoreRoutes(), h.GetOAuthRoutes()...)
}

// BuildChain creates a middleware chain for a specific route
func (h *AuthHandler) BuildChain(routeName string, finalHandler http.Handler) http.Handler {
	// Start with the final handler
	handler := finalHandler

	// Apply hook middleware first (closest to the actual handler)
	handler = h.withHooks(routeName, handler)
	// Apply rate limiter middleware if enabled
	if h.Auth.Config.Features.EnableRateLimiter {
		if _, needsRateLimit := h.Auth.Config.Security.RateLimiter.Routes[routeName]; needsRateLimit {
			handler = middleware.RateLimiterMiddleware(*h.Auth.RateLimiter, &h.Auth.Config.Security.RateLimiter, routeName, handler.ServeHTTP)
		}
	}

	return handler
}

// withHooks applies hook middleware to the handler
func (h *AuthHandler) withHooks(routeName string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Execute pre-hooks
		if h.Auth.HookManager != nil && h.Auth.HookManager.GetBeforeHook(routeName) != nil {
			if !h.Auth.HookManager.ExecuteBeforeHooks(routeName, w, r) {
				return
			}
		}
		// Execute the main handler
		handler.ServeHTTP(w, r)
	})
}
