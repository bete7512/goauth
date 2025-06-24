// Package auth - Clean authentication library (HTTP only)
package auth

import (
	"net/http"

	"github.com/bete7512/goauth/internal/api"
	"github.com/bete7512/goauth/pkg/config"
)

// AuthService is the main authentication service
type AuthService struct {
	*api.AuthHandler
}

// NewAuth creates a new authentication service
func NewAuth(conf config.Config) (*AuthService, error) {
	return NewBuilder().
		WithConfig(conf).
		Build()
}

// GetAuthMiddleware returns authentication middleware for protecting routes
func (a *AuthService) GetAuthMiddleware() func(http.Handler) http.Handler {
	return a.AuthHandler.GetAuthMiddleware()
}

// GetRateLimitMiddleware returns rate limiting middleware
func (a *AuthService) GetRateLimitMiddleware(routeName string) func(http.Handler) http.Handler {
	return a.AuthHandler.GetRateLimitMiddleware(routeName)
}

// GetRoutes returns all auth routes for manual registration
// This allows frameworks to register individual routes properly
func (a *AuthService) GetRoutes() []api.RouteInfo {
	return a.AuthHandler.GetRoutes()
}

// GetWrappedHandler returns a handler with all middleware applied
func (a *AuthService) GetWrappedHandler(routeInfo api.RouteInfo) http.HandlerFunc {
	return a.AuthHandler.GetWrappedHandler(routeInfo)
}

// Hook management - allows users to add custom logic before/after auth operations
func (a *AuthService) RegisterBeforeHook(route string, hook func(http.ResponseWriter, *http.Request) (bool, error)) error {
	return a.AuthHandler.RegisterBeforeHook(route, hook)
}

func (a *AuthService) RegisterAfterHook(route string, hook func(http.ResponseWriter, *http.Request) (bool, error)) error {
	return a.AuthHandler.RegisterAfterHook(route, hook)
}
