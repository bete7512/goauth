package middleware

import (
	"net/http"
	"strings"
)

// MiddlewareFunc is a standard HTTP middleware function
type MiddlewareFunc func(http.Handler) http.Handler

// MiddlewareConfig defines middleware configuration
type MiddlewareConfig struct {
	Name        string
	Middleware  MiddlewareFunc
	Priority    int
	ApplyTo     []string // Route names or patterns
	ExcludeFrom []string // Route names or patterns to exclude
	Global      bool     // Apply to all routes
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
func matchPattern(pattern, routeName string) bool {
	if pattern == "*" {
		return true
	}

	if pattern == routeName {
		return true
	}

	// Simple wildcard matching
	if strings.Contains(pattern, "*") {
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			prefix := parts[0]
			suffix := parts[1]
			return strings.HasPrefix(routeName, prefix) && strings.HasSuffix(routeName, suffix)
		}
	}

	return false
}

// Common middleware helpers

// CORS creates a CORS middleware
func CORS(allowedOrigins []string, allowedMethods []string) MiddlewareFunc {
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
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
				// Generate a simple request ID
				requestID = generateRequestID()
			}
			w.Header().Set("X-Request-ID", requestID)
			next.ServeHTTP(w, r)
		})
	}
}

// generateRequestID generates a simple request ID
func generateRequestID() string {
	// In production, use UUID or similar
	return "req-" + strings.Replace(strings.Replace(http.TimeFormat, " ", "-", -1), ":", "-", -1)
}
