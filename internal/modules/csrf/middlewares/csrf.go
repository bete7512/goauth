package middlewares

import (
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/modules/csrf/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// NewCSRFMiddleware creates a CSRF protection middleware using the double-submit cookie pattern.
//
// Validation requires BOTH:
//  1. A token in the cookie (sent automatically by the browser)
//  2. The same token in a header or form field (must be set explicitly by the client)
//
// An attacker can trigger the browser to send the cookie on a cross-origin request,
// but cannot read the cookie value to include it in the header. This is the defense.
func NewCSRFMiddleware(service services.CSRFService, cfg *config.CSRFModuleConfig) func(http.Handler) http.Handler {
	protectedMethods := cfg.ProtectedMethods
	if len(protectedMethods) == 0 {
		protectedMethods = []string{"POST", "PUT", "DELETE", "PATCH"}
	}

	protectedSet := make(map[string]bool, len(protectedMethods))
	for _, m := range protectedMethods {
		protectedSet[m] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip safe methods
			if !protectedSet[r.Method] {
				next.ServeHTTP(w, r)
				return
			}

			// Skip excluded paths
			for _, path := range cfg.ExcludePaths {
				if strings.HasPrefix(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Get token from cookie (sent automatically by browser)
			cookieToken := ""
			if cookie, err := r.Cookie(service.CookieName()); err == nil {
				cookieToken = cookie.Value
			}

			// Get token from header or form field (must be set explicitly by client)
			submittedToken := r.Header.Get(service.HeaderName())
			if submittedToken == "" {
				submittedToken = r.FormValue(service.FormFieldName())
			}
			
			// Both must be present
			if cookieToken == "" || submittedToken == "" {
				http_utils.RespondError(w, http.StatusForbidden, string(types.ErrInvalidCSRF), "CSRF token missing")
				return
			}

			// Both must match (constant-time comparison)
			if !service.TokensMatch(cookieToken, submittedToken) {
				http_utils.RespondError(w, http.StatusForbidden, string(types.ErrInvalidCSRF), "CSRF token mismatch")
				return
			}

			// HMAC signature must be valid and token must not be expired
			if !service.ValidateToken(cookieToken) {
				http_utils.RespondError(w, http.StatusForbidden, string(types.ErrInvalidCSRF), "Invalid CSRF token")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
