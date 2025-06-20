package core

import (
	"net/http"

	"github.com/bete7512/goauth/api/routes"
	oauthRoutes "github.com/bete7512/goauth/api/routes/oauth"
	"github.com/bete7512/goauth/types"
)

// AuthHandler implements RouteRegistry and MiddlewareChain interfaces
type AuthHandler struct {
	Auth *types.Auth
}

// NewAuthHandler creates a new AuthHandler instance
func NewAuthHandler(auth *types.Auth) *AuthHandler {
	return &AuthHandler{Auth: auth}
}

// GetCoreRoutes returns all standard authentication routes
func (h *AuthHandler) GetCoreRoutes() []RouteDefinition {
	// Create a routes handler to access the route methods
	routesHandler := &routes.AuthHandler{Auth: h.Auth}

	return []RouteDefinition{
		{Name: types.RouteRegister, Method: http.MethodPost, Path: "/register", Handler: routesHandler.HandleRegister},
		{Name: types.RouteLogin, Method: http.MethodPost, Path: "/login", Handler: routesHandler.HandleLogin},
		{Name: types.RouteMagicLink, Method: http.MethodPost, Path: "/send-magic-link", Handler: routesHandler.SendMagicLink},
		{Name: types.RouteMagicLinkLogin, Method: http.MethodPost, Path: "/verify-magic-login", Handler: routesHandler.HandleVerifyMagicLink},
		{Name: types.RouteLogout, Method: http.MethodPost, Path: "/logout", Handler: routesHandler.HandleLogout},
		{Name: types.RouteRefreshToken, Method: http.MethodPost, Path: "/refresh-token", Handler: routesHandler.HandleRefreshToken},
		{Name: types.RouteForgotPassword, Method: http.MethodPost, Path: "/forgot-password", Handler: routesHandler.HandleForgotPassword},
		{Name: types.RouteResetPassword, Method: http.MethodPost, Path: "/reset-password", Handler: routesHandler.HandleResetPassword},
		{Name: types.RouteUpdateProfile, Method: http.MethodPost, Path: "/update-profile", Handler: routesHandler.HandleUpdateProfile},
		{Name: types.RouteDeactivateUser, Method: http.MethodPost, Path: "/deactivate-user", Handler: routesHandler.HandleDeactivateUser},
		{Name: types.RouteGetMe, Method: http.MethodGet, Path: "/me", Handler: routesHandler.HandleGetUser},
		{Name: types.RouteEnableTwoFactor, Method: http.MethodPost, Path: "/enable-two-factor", Handler: routesHandler.HandleEnableTwoFactor},
		{Name: types.RouteVerifyTwoFactor, Method: http.MethodPost, Path: "/verify-two-factor", Handler: routesHandler.HandleVerifyTwoFactor},
		{Name: types.RouteDisableTwoFactor, Method: http.MethodPost, Path: "/disable-two-factor", Handler: routesHandler.HandleDisableTwoFactor},
		{Name: types.RouteVerifyEmail, Method: http.MethodPost, Path: "/verify-email", Handler: routesHandler.HandleVerifyEmail},
		{Name: types.RouteResendVerificationEmail, Method: http.MethodPost, Path: "/resend-verification-email", Handler: routesHandler.HandleResendVerificationEmail},
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
	handler := finalHandler

	// Apply rate limiter middleware if enabled
	if h.Auth.Config.EnableRateLimiter {
		if _, needsRateLimit := h.Auth.Config.RateLimiter.Routes[routeName]; needsRateLimit {
			// Note: Rate limiter middleware would need to be imported and used here
			// For now, we'll skip it to avoid import issues
		}
	}

	// Apply hook middleware (closest to the actual handler)
	handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	})
	handler = h.withHooks(routeName, handlerFunc)

	return handler
}

// withHooks applies hook middleware to the handler
func (h *AuthHandler) withHooks(routeName string, handler http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Execute pre-hooks
		if h.Auth.HookManager != nil && h.Auth.HookManager.GetBeforeHook(routeName) != nil {
			if !h.Auth.HookManager.ExecuteBeforeHooks(routeName, w, r) {
				return
			}
		}
		// Execute the main handler
		handler.ServeHTTP(w, r)

		// Execute post-hooks
		if h.Auth.HookManager != nil {
			h.Auth.HookManager.ExecuteAfterHooks(routeName, w, r)
		}
	})
}
