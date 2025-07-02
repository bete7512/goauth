package middlewares

import (
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
)

// CSRFMiddleware validates CSRF tokens for protected routes
func (m *Middleware) CSRFMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get CSRF token from header
		csrfToken := r.Header.Get("X-CSRF-Token")
		if csrfToken == "" {
			utils.RespondWithError(w, http.StatusForbidden, "csrf token is required", nil)
			return
		}

		// Get user ID from request context (set by auth middleware)
		userID := r.Context().Value("user_id")
		if userID == nil {
			utils.RespondWithError(w, http.StatusUnauthorized, "user not authenticated", nil)
			return
		}

		// Validate CSRF token
		valid, err := m.Auth.CSRFManager.ValidateToken(r.Context(), csrfToken, userID.(string))
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "csrf validation failed", err)
			return
		}
		if !valid {
			utils.RespondWithError(w, http.StatusForbidden, "invalid csrf token", nil)
			return
		}

		next.ServeHTTP(w, r)
	}
}
