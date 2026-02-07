package middlewares

import (
	"context"
	"net/http"

	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// AdminAuthMiddleware verifies that the authenticated user is a super admin
type AdminAuthMiddleware struct {
	deps config.ModuleDependencies
}

// NewAdminAuthMiddleware creates a new AdminAuthMiddleware
func NewAdminAuthMiddleware(deps config.ModuleDependencies) *AdminAuthMiddleware {
	return &AdminAuthMiddleware{
		deps: deps,
	}
}

// Middleware returns the HTTP middleware function
func (m *AdminAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get userID from context (set by core.AuthMiddleware)
		userID, ok := r.Context().Value(types.UserIDKey).(string)
		if !ok || userID == "" {
			http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "authentication required")
			return
		}

		// Fetch user from storage
		coreStorage := m.deps.Storage.Core()
		if coreStorage == nil {
			http_utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "core storage not available")
			return
		}

		user, err := coreStorage.Users().FindByID(r.Context(), userID)
		if err != nil {
			http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user not found")
			return
		}

		// Check if user is super admin
		if !user.IsSuperAdmin {
			http_utils.RespondError(w, http.StatusForbidden, string(types.ErrForbidden), "super admin access required")
			return
		}

		// Add full user object to context for audit logging
		ctx := context.WithValue(r.Context(), types.UserKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AdminAuthMiddlewareFunc is a helper function that creates and returns the middleware
// This maintains backward compatibility with the old function signature
func AdminAuthMiddlewareFunc(deps config.ModuleDependencies) func(http.Handler) http.Handler {
	middleware := NewAdminAuthMiddleware(deps)
	return middleware.Middleware
}
