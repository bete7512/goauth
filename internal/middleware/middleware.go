package middleware

import (
	"net/http"
	"strings"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// MiddlewareFunc is a standard HTTP middleware function
type MiddlewareFunc func(http.Handler) http.Handler

// MiddlewareConfig defines middleware configuration
type MiddlewareConfig struct {
	Name        string
	Middleware  MiddlewareFunc
	Priority    int
	ApplyTo     []types.RouteName // Route names or patterns (e.g. types.RouteSignup, "core.*")
	ExcludeFrom []types.RouteName // Route names or patterns to exclude
	Global      bool              // Apply to all routes
}

// Manager manages and applies middlewares
type Manager struct {
	middlewares []MiddlewareConfig
}

// NewManager creates a new middleware manager
func NewManager() *Manager {
	return &Manager{
		middlewares: make([]MiddlewareConfig, 0),
	}
}

// Register registers a middleware with configuration
func (m *Manager) Register(config MiddlewareConfig) {
	m.middlewares = append(m.middlewares, config)

	// Sort by priority (higher priority first)
	for i := len(m.middlewares) - 1; i > 0; i-- {
		if m.middlewares[i].Priority > m.middlewares[i-1].Priority {
			m.middlewares[i], m.middlewares[i-1] = m.middlewares[i-1], m.middlewares[i]
		}
	}
}

// Apply applies middlewares to a handler for a specific route
func (m *Manager) Apply(routeName string, handler http.Handler) http.Handler {
	// Apply middlewares in reverse order (last registered, first executed in chain)
	for i := len(m.middlewares) - 1; i >= 0; i-- {
		mw := m.middlewares[i]

		// Check if middleware should be applied
		if m.shouldApply(mw, routeName) {
			handler = mw.Middleware(handler)
		}
	}

	return handler
}

// ApplyWithRouteMiddlewares applies middlewares to a handler based on route's middleware list
// This method considers both global middlewares and route-specific middlewares
func (m *Manager) ApplyWithRouteMiddlewares(routeName string, handler http.Handler, routeMiddlewares []string) http.Handler {
	// Create a map of route-required middlewares for fast lookup
	requiredMiddlewares := make(map[string]bool)
	for _, mwName := range routeMiddlewares {
		requiredMiddlewares[mwName] = true
	}

	// Apply middlewares in reverse order (last registered, first executed in chain)
	for i := len(m.middlewares) - 1; i >= 0; i-- {
		mw := m.middlewares[i]

		// Apply middleware if:
		// 1. It's global and not excluded
		// 2. It's in the route's middleware list
		// 3. Its ApplyTo patterns match this route name
		shouldApply := false

		if mw.Global {
			// Check exclusions for global middlewares
			excluded := false
			for _, exclude := range mw.ExcludeFrom {
				if matchPattern(exclude, routeName) {
					excluded = true
					break
				}
			}
			shouldApply = !excluded
		} else if requiredMiddlewares[mw.Name] {
			// Route explicitly requires this middleware
			shouldApply = true
		} else if len(mw.ApplyTo) > 0 {
			// Check if middleware's ApplyTo patterns match this route
			for _, pattern := range mw.ApplyTo {
				if matchPattern(pattern, routeName) {
					shouldApply = true
					break
				}
			}
			// Check exclusions
			if shouldApply {
				for _, exclude := range mw.ExcludeFrom {
					if matchPattern(exclude, routeName) {
						shouldApply = false
						break
					}
				}
			}
		}

		if shouldApply {
			handler = mw.Middleware(handler)
		}
	}

	return handler
}

// ApplyGlobal applies only global middlewares to a handler
func (m *Manager) ApplyGlobal(handler http.Handler) http.Handler {
	for i := len(m.middlewares) - 1; i >= 0; i-- {
		mw := m.middlewares[i]
		if mw.Global {
			handler = mw.Middleware(handler)
		}
	}
	return handler
}

// Chain chains multiple middleware functions
func Chain(middlewares ...MiddlewareFunc) MiddlewareFunc {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

// shouldApply determines if middleware should be applied to a route
func (m *Manager) shouldApply(mw MiddlewareConfig, routeName string) bool {
	// If global, always apply
	if mw.Global {
		// Check exclusions
		for _, exclude := range mw.ExcludeFrom {
			if matchPattern(exclude, routeName) {
				return false
			}
		}
		return true
	}

	// If no specific routes defined, don't apply
	if len(mw.ApplyTo) == 0 {
		return false
	}

	// Check if route matches any patterns
	for _, pattern := range mw.ApplyTo {
		if matchPattern(pattern, routeName) {
			// Check exclusions
			for _, exclude := range mw.ExcludeFrom {
				if matchPattern(exclude, routeName) {
					return false
				}
			}
			return true
		}
	}

	return false
}

// matchPattern matches a route name against a pattern
// Supports wildcards: * (any characters), ? (single character)
func matchPattern(pattern types.RouteName, routeName string) bool {
	p := string(pattern)
	if p == "*" {
		return true
	}

	if p == routeName {
		return true
	}

	// Simple wildcard matching
	if strings.Contains(p, "*") {
		parts := strings.Split(p, "*")
		if len(parts) == 2 {
			return strings.HasPrefix(routeName, parts[0]) && strings.HasSuffix(routeName, parts[1])
		}
	}

	return false
}

// Common middleware helpers

// CORS creates a CORS middleware
func CORS(allowedOrigins []string, allowedMethods []string, allowedHeaders []string) MiddlewareFunc {
	// Default headers if none provided
	headers := "Content-Type, Authorization"
	if len(allowedHeaders) > 0 {
		headers = strings.Join(allowedHeaders, ", ")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			allowed := false
			for _, allowedOrigin := range allowedOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", headers)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequestID adds a unique request ID to each request
func RequestID() MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = generateRequestID()
			}
			w.Header().Set("X-Request-ID", requestID)
			next.ServeHTTP(w, r)
		})
	}
}

func generateRequestID() string {
	return "req-" + uuid.NewString()
}
