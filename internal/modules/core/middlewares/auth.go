package middlewares

import (
	"context"
	"errors"
	"net/http"
	"strings"

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
		accessToken := "goauth_access_" + m.Config.Security.Session.Name
		claims, err := m.getClaimsFromRequest(r, accessToken)
		if err != nil {
			http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), err.Error())
			return
		}

		userID, ok := claims["user_id"].(string)
		if !ok || userID == "" {
			http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user id not found in request")
			return
		}

		ctx := context.WithValue(r.Context(), types.UserIDKey, userID)

		// Extract session_id if present (session-based JWTs embed it)
		if sessionID, ok := claims["session_id"].(string); ok && sessionID != "" {
			ctx = context.WithValue(ctx, types.SessionIDKey, sessionID)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getClaimsFromRequest extracts the JWT token and returns validated claims
func (m *AuthMiddleware) getClaimsFromRequest(r *http.Request, accessToken string) (map[string]interface{}, error) {
	token := m.extractToken(r, accessToken)
	if token == "" {
		return nil, errors.New("no authentication token provided")
	}

	claims, err := m.SecurityManager.ValidateJWTToken(token)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func (m *AuthMiddleware) extractToken(r *http.Request, accessToken string) string {
	cookie, err := r.Cookie(accessToken)
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// TODO: if cookie only return from here

	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
		return bearerToken[7:]
	}
	return ""
}

func (m *AuthMiddleware) AuthMiddlewareFunc(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.AuthMiddleware(http.HandlerFunc(next)).ServeHTTP(w, r)
	})
}
