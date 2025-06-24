// Package goauth - Clean authentication library (HTTP only)
package goauth

import (
	"net/http"

	"github.com/bete7512/goauth/api"
	"github.com/bete7512/goauth/config"
)

// AuthService is the main authentication service
type AuthService struct {
	*api.AuthService
}

// NewAuth creates a new authentication service
func NewAuth(conf config.Config) (*AuthService, error) {
	return NewBuilder().
		WithConfig(conf).
		Build()
}

// ServeHTTP implements http.Handler - this is the key interface
// Users mount this on their router: mux.Handle("/auth/", authService)
func (a *AuthService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.AuthService.ServeHTTP(w, r)
}

// GetAuthMiddleware returns authentication middleware for protecting routes
// Usage: protectedHandler := authService.GetAuthMiddleware()(yourHandler)
func (a *AuthService) GetAuthMiddleware() func(http.Handler) http.Handler {
	return a.AuthService.GetAuthMiddleware()
}

// GetRateLimitMiddleware returns rate limiting middleware
// Usage: rateLimitedHandler := authService.GetRateLimitMiddleware("login")(yourHandler)
func (a *AuthService) GetRateLimitMiddleware(routeName string) func(http.Handler) http.Handler {
	return a.AuthService.GetRateLimitMiddleware(routeName)
}

// GetRoutes returns all auth routes for manual registration
// This allows frameworks to register individual routes properly
func (a *AuthService) GetRoutes() []api.RouteInfo {
	return a.AuthService.GetRoutes()
}

// GetWrappedHandler returns a handler with all middleware applied
func (a *AuthService) GetWrappedHandler(routeInfo api.RouteInfo) http.HandlerFunc {
	return a.AuthService.GetWrappedHandler(routeInfo)
}

// Hook management - allows users to add custom logic before/after auth operations
func (a *AuthService) RegisterBeforeHook(route string, hook func(http.ResponseWriter, *http.Request) (bool, error)) error {
	return a.AuthService.RegisterBeforeHook(route, hook)
}

func (a *AuthService) RegisterAfterHook(route string, hook func(http.ResponseWriter, *http.Request) (bool, error)) error {
	return a.AuthService.RegisterAfterHook(route, hook)
}
