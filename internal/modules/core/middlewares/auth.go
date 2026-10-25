package middlewares

import (
	"context"
	"github.com/bete7512/goauth/internal/security"
	"net/http"

	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type AuthMiddleware struct {
	Config          *config.Config
	SecurityManager types.SecurityManager
}

func NewAuthMiddleware(config *config.Config, securityManager types.SecurityManager) *AuthMiddleware {
	return &AuthMiddleware{
		Config:          config,
		SecurityManager: securityManager,
	}
}

// AuthMiddleware validates user authentication but doesn't require admin privileges
func (m *AuthMiddleware) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := http_utils.AccessCredential(r, m.Config.Security)
		principal, err := security.ValidateAccess(r.Context(), m.Config, m.SecurityManager, token)
		if err != nil {
			http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "invalid access credential")
			return
		}
		ctx := types.WithPrincipal(r.Context(), principal)
		ctx = context.WithValue(ctx, types.UserIDKey, principal.UserID)
		if principal.SessionID != "" {
			ctx = context.WithValue(ctx, types.SessionIDKey, principal.SessionID)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *AuthMiddleware) AuthMiddlewareFunc(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.AuthMiddleware(http.HandlerFunc(next)).ServeHTTP(w, r)
	})
}
