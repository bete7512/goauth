package frameworks

import (
	"net/http"

	"github.com/bete7512/goauth/api/core"
)

// StandardAdapter adapts the core authentication routes to the standard HTTP framework
type StandardAdapter struct {
	handler *core.AuthHandler
}

// NewStandardAdapter creates a new Standard HTTP adapter
func NewStandardAdapter(handler *core.AuthHandler) *StandardAdapter {
	return &StandardAdapter{handler: handler}
}

// SetupRoutes registers all authentication routes with standard HTTP ServeMux
func (a *StandardAdapter) SetupRoutes(router interface{}) error {
	serveMux, ok := router.(*http.ServeMux)
	if !ok {
		return &InvalidRouterError{Expected: "http.ServeMux", Got: router}
	}

	// Setup Swagger if enabled
	if a.handler.Auth.Config.App.Swagger.Enable {
		// TODO: Add Swagger setup for Standard HTTP
	}

	// Get all routes
	allRoutes := a.handler.GetAllRoutes()

	// Register routes with ServeMux
	for _, route := range allRoutes {
		// Build the middleware chain
		chainedHandler := a.handler.BuildChain(route.Name, http.HandlerFunc(route.Handler))

		// Create the full path
		fullPath := a.handler.Auth.Config.App.BasePath + route.Path

		// Register the route
		serveMux.HandleFunc(fullPath, func(w http.ResponseWriter, r *http.Request) {
			// Only handle the specific HTTP method
			if r.Method != route.Method {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			chainedHandler.ServeHTTP(w, r)
		})
	}

	return nil
}

// GetMiddleware returns Standard HTTP-specific middleware
func (a *StandardAdapter) GetMiddleware() interface{} {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Global middleware for Standard HTTP
			next.ServeHTTP(w, r)
		})
	}
}

// GetFrameworkType returns the framework type
func (a *StandardAdapter) GetFrameworkType() core.FrameworkType {
	return core.FrameworkStandard
}
