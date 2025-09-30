package middlewares

import (
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/types"
)

// CSRFMiddleware validates CSRF tokens for protected routes
func (m *Middleware) CSRFMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get CSRF token from header
		csrfToken := r.Header.Get("X-CSRF-Token")
		if csrfToken == "" {
			utils.RespondError(w, http.StatusForbidden, string(types.ErrForbidden), "csrf token is required")
			return
		}

		// Get user ID from request context (set by auth middleware)
		userID := r.Context().Value("user_id")
		if userID == nil {
			utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user not authenticated")
			return
		}

		// Validate CSRF token
		valid, err := m.Auth.CSRFManager.ValidateToken(r.Context(), csrfToken, userID.(string))
		if err != nil {
			utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), err.Error())
			return
		}
		if !valid {
			utils.RespondError(w, http.StatusForbidden, string(types.ErrForbidden), "invalid csrf token")
			return
		}

		next.ServeHTTP(w, r)
	}
}
