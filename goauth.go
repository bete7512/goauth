package goauth

import (
	"net/http"

	"github.com/bete7512/goauth/api"
	"github.com/bete7512/goauth/api/core"
	"github.com/bete7512/goauth/hooks"
	"github.com/bete7512/goauth/interfaces"
	"github.com/bete7512/goauth/logger"
	tokenManager "github.com/bete7512/goauth/tokens"
	"github.com/bete7512/goauth/types"
	"github.com/gin-gonic/gin"
)

// AuthService is the main service for the authentication system.
type AuthService struct {
	Config           types.Config
	Repository       interfaces.RepositoryFactory
	HookManager      *hooks.HookManager
	RateLimiter      types.RateLimiter
	RecaptchaManager types.CaptchaVerifier
	Logger           logger.Log

	// authContext holds the shared dependencies for handlers.
	authContext *types.Auth

	// Unified API for all frameworks
	authAPI *api.AuthAPI
}

// NewAuth uses a builder to create and initialize a new AuthService.
// This is a simple entry point for common use cases.
func NewAuth(conf types.Config) (*AuthService, error) {
	return NewBuilder().
		WithConfig(conf).
		Build()
}

// RegisterBeforeHook registers a hook to run before a specific route's logic.
func (a *AuthService) RegisterBeforeHook(route string, hook hooks.RouteHook) error {
	return a.HookManager.RegisterBeforeHook(route, hook)
}

// RegisterAfterHook registers a hook to run after a specific route's logic.
func (a *AuthService) RegisterAfterHook(route string, hook hooks.RouteHook) error {
	return a.HookManager.RegisterAfterHook(route, hook)
}

// initAuthContext initializes the shared context for all handlers.
// This is called internally by the builder.
func (a *AuthService) initAuthContext() {
	if a.authContext == nil {
		a.authContext = &types.Auth{
			Config:       a.Config,
			Repository:   a.Repository,
			HookManager:  a.HookManager,
			TokenManager: tokenManager.NewTokenManager(a.Config),
			RateLimiter:  &a.RateLimiter,
			Logger:       a.Logger,
		}
	}
}

// getAuthAPI lazily initializes and returns a singleton AuthAPI.
func (a *AuthService) getAuthAPI() *api.AuthAPI {
	if a.authAPI == nil {
		a.initAuthContext()
		a.authAPI = api.NewAuthAPI(a.authContext)
	}
	return a.authAPI
}

// GetSupportedFrameworks returns a list of all supported frameworks.
func (a *AuthService) GetSupportedFrameworks() []core.FrameworkType {
	return a.getAuthAPI().GetSupportedFrameworks()
}

// GetRoutes returns all available routes for inspection.
func (a *AuthService) GetRoutes() []core.RouteDefinition {
	return a.getAuthAPI().GetRoutes()
}

// GetCoreRoutes returns only the core authentication routes.
func (a *AuthService) GetCoreRoutes() []core.RouteDefinition {
	return a.getAuthAPI().GetCoreRoutes()
}

// GetOAuthRoutes returns only the OAuth provider routes.
func (a *AuthService) GetOAuthRoutes() []core.RouteDefinition {
	return a.getAuthAPI().GetOAuthRoutes()
}

// SetupRoutes configures authentication routes for the specified framework.
func (a *AuthService) SetupRoutes(frameworkType core.FrameworkType, router interface{}) error {
	return a.getAuthAPI().SetupRoutes(frameworkType, router)
}

// GetMiddleware returns framework-specific middleware.
func (a *AuthService) GetMiddleware(frameworkType core.FrameworkType) (interface{}, error) {
	return a.getAuthAPI().GetMiddleware(frameworkType)
}

// Framework-specific convenience methods

// Gin Framework Methods

// GetGinAuthMiddleware returns a Gin middleware.
func (a *AuthService) GetGinAuthMiddleware(r *gin.Engine) gin.HandlerFunc {
	middleware, err := a.getAuthAPI().GetMiddleware(core.FrameworkGin)
	if err != nil {
		a.Logger.Errorf("Failed to get Gin middleware: %v", err)
		return func(c *gin.Context) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Middleware initialization failed"})
		}
	}

	// Type assert the middleware to gin.HandlerFunc
	if ginMiddleware, ok := middleware.(gin.HandlerFunc); ok {
		return ginMiddleware
	}

	// Fallback middleware
	return func(c *gin.Context) {
		c.Next()
	}
}

// GetGinAuthRoutes sets up all authentication routes on the provided Gin engine.
func (a *AuthService) GetGinAuthRoutes(r *gin.Engine) error {
	return a.getAuthAPI().SetupGinRoutes(r)
}

// HTTP Framework Methods

// GetHttpAuthMiddleware returns a standard http.Handler middleware.
func (a *AuthService) GetHttpAuthMiddleware(next http.Handler) http.Handler {
	middleware, err := a.getAuthAPI().GetMiddleware(core.FrameworkStandard)
	if err != nil {
		a.Logger.Errorf("Failed to get HTTP middleware: %v", err)
		return next
	}

	// Type assert the middleware to http.Handler
	if httpMiddleware, ok := middleware.(func(http.Handler) http.Handler); ok {
		return httpMiddleware(next)
	}

	// Fallback middleware
	return next
}

// GetHttpAuthRoutes sets up all authentication routes on the provided http.ServeMux.
func (a *AuthService) GetHttpAuthRoutes(s *http.ServeMux) error {
	return a.getAuthAPI().SetupStandardRoutes(s)
}

// Additional framework-specific convenience methods

// SetupChiRoutes sets up authentication routes for Chi framework.
func (a *AuthService) SetupChiRoutes(router interface{}) error {
	return a.getAuthAPI().SetupChiRoutes(router)
}

// SetupEchoRoutes sets up authentication routes for Echo framework.
func (a *AuthService) SetupEchoRoutes(router interface{}) error {
	return a.getAuthAPI().SetupEchoRoutes(router)
}

// SetupFiberRoutes sets up authentication routes for Fiber framework.
func (a *AuthService) SetupFiberRoutes(router interface{}) error {
	return a.getAuthAPI().SetupFiberRoutes(router)
}

// SetupGorillaMuxRoutes sets up authentication routes for Gorilla Mux framework.
func (a *AuthService) SetupGorillaMuxRoutes(router interface{}) error {
	return a.getAuthAPI().SetupGorillaMuxRoutes(router)
}

// SetupStandardRoutes sets up authentication routes for Standard HTTP framework.
func (a *AuthService) SetupStandardRoutes(router interface{}) error {
	return a.getAuthAPI().SetupStandardRoutes(router)
}
