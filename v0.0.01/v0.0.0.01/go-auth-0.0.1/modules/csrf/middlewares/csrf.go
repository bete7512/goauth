package middlewares

import (
	"net/http"
	"strings"

	"github.com/bete7512/goauth/modules/csrf/services"
)

type CSRFConfig struct {
	ExcludePaths     []string
	ProtectedMethods []string
}

// NewCSRFMiddleware creates a CSRF protection middleware
func NewCSRFMiddleware(service *services.CSRFService, config interface{}) func(http.Handler) http.Handler {
	// Extract config
	var excludePaths []string
	var protectedMethods []string

	// Try to extract config values using type assertion
	type csrfConfig interface {
		GetExcludePaths() []string
		GetProtectedMethods() []string
	}

	// Use reflection-free approach
	switch cfg := config.(type) {
	case *CSRFConfig:
		excludePaths = cfg.ExcludePaths
		protectedMethods = cfg.ProtectedMethods
	case CSRFConfig:
		excludePaths = cfg.ExcludePaths
		protectedMethods = cfg.ProtectedMethods
	}

	// Default protected methods
	if len(protectedMethods) == 0 {
		protectedMethods = []string{"POST", "PUT", "DELETE", "PATCH"}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path is excluded
			for _, path := range excludePaths {
				if strings.HasPrefix(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Check if method requires protection
			needsProtection := false
			for _, method := range protectedMethods {
				if r.Method == method {
					needsProtection = true
					break
				}
			}

			if !needsProtection {
				next.ServeHTTP(w, r)
				return
			}

			// Get token from header
			token := r.Header.Get(service.GetHeaderName())

			// If not in header, try form field
			if token == "" {
				token = r.FormValue(service.GetFormFieldName())
			}

			// If not in form, try cookie
			if token == "" {
				cookie, err := r.Cookie(service.GetCookieName())
				if err == nil {
					token = cookie.Value
				}
			}

			// Validate token
			if !service.ValidateToken(token) {
				http.Error(w, "CSRF token validation failed", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
