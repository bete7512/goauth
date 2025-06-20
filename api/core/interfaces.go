package core

import (
	"net/http"
)

// FrameworkType represents supported web frameworks
type FrameworkType string

const (
	FrameworkGin        FrameworkType = "gin"
	FrameworkChi        FrameworkType = "chi"
	FrameworkEcho       FrameworkType = "echo"
	FrameworkFiber      FrameworkType = "fiber"
	FrameworkGorillaMux FrameworkType = "gorilla-mux"
	FrameworkStandard   FrameworkType = "standard"
)

// RouteDefinition defines a framework-agnostic route
type RouteDefinition struct {
	Name    string           // Unique name for the route
	Method  string           // HTTP method
	Path    string           // URL path
	Handler http.HandlerFunc // Core logic handler
}

// FrameworkAdapter defines the interface for framework-specific adapters
type FrameworkAdapter interface {
	// SetupRoutes registers all authentication routes with the framework
	SetupRoutes(router interface{}) error

	// GetMiddleware returns framework-specific middleware
	GetMiddleware() interface{}

	// GetFrameworkType returns the framework type
	GetFrameworkType() FrameworkType
}

// RouteRegistry manages route definitions and provides access to them
type RouteRegistry interface {
	// GetCoreRoutes returns all standard authentication routes
	GetCoreRoutes() []RouteDefinition

	// GetOAuthRoutes returns all OAuth provider routes
	GetOAuthRoutes() []RouteDefinition

	// GetAllRoutes returns all routes (core + OAuth)
	GetAllRoutes() []RouteDefinition
}

// MiddlewareChain builds middleware chains for routes
type MiddlewareChain interface {
	// BuildChain creates a middleware chain for a specific route
	BuildChain(routeName string, finalHandler http.Handler) http.Handler
}
