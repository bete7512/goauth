package middlewares

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/security"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type AuthMiddleware struct {
	Config          *config.Config
	SecurityManager *security.SecurityManager
}

func NewAuthMiddleware(config *config.Config, securityManager *security.SecurityManager) *AuthMiddleware {
	return &AuthMiddleware{
		Config:          config,
		SecurityManager: securityManager,
	}
}

// AuthMiddleware validates user authentication but doesn't require admin privileges
func (m *AuthMiddleware) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken := "goauth_access_" + m.Config.Security.Session.Name
		userID, err := m.getUserIdFromRequest(r, accessToken)
		if err != nil {
			http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), err.Error())
			return
		}
		if userID == "" {
			http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user id not found in request")
			return
		}

		// Add user ID to context for downstream handlers
		ctx := context.WithValue(r.Context(), types.UserIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
		return
	})
}

// getUserIdFromRequest extracts and validates the token from a request
func (m *AuthMiddleware) getUserIdFromRequest(r *http.Request, accessToken string) (string, error) {
	token := m.extractToken(r, accessToken)
	if token == "" {
		return "", errors.New("no authentication token provided")
	}

	claims, err := m.SecurityManager.ValidateJWTToken(token)
	if err != nil {
		return "", err
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	return userID, nil
}

func (m *AuthMiddleware) extractToken(r *http.Request, accessToken string) string {
	cookie, err := r.Cookie(accessToken)
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

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


