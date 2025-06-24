package auth

import (
	"net/http"
)

// RouteInfo represents information about an auth route
type RouteInfo struct {
	Method string
	Path   string
	Name   string
}

// HookFunc represents a hook function that can be executed before or after auth operations
type HookFunc func(http.ResponseWriter, *http.Request) (bool, error)

// AuthService is the main authentication service interface
// type AuthService interface {
// 	// GetAuthMiddleware returns authentication middleware for protecting routes
// 	GetAuthMiddleware() func(http.Handler) http.Handler

// 	// GetRateLimitMiddleware returns rate limiting middleware for specific routes
// 	GetRateLimitMiddleware(routeName string) func(http.Handler) http.Handler

// 	// GetRoutes returns all auth routes for manual registration
// 	GetRoutes() []RouteInfo

// 	// GetWrappedHandler returns a handler with all middleware applied
// 	GetWrappedHandler(routeInfo RouteInfo) http.HandlerFunc

// 	// RegisterBeforeHook registers a hook to be executed before auth operations
// 	RegisterBeforeHook(route string, hook HookFunc) error

// 	// RegisterAfterHook registers a hook to be executed after auth operations
// 	RegisterAfterHook(route string, hook HookFunc) error
// }
