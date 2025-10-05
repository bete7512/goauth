package middlewares

import (
	"context"
	"errors"
	"log"
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
		log.Println("AuthMiddleware")
		userID, err := m.getUserIdFromRequest(r, m.Config.Security.Cookie.Name)
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
func (m *AuthMiddleware) getUserIdFromRequest(r *http.Request, cookieName string) (string, error) {
	token := m.extractToken(r, cookieName)
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

func (m *AuthMiddleware) extractToken(r *http.Request, cookieName string) string {
	// switch m.Config.Security.AuthenticationType {
	// case config.AuthenticationTypeCookie:
	// 	cookie, err := r.Cookie("__goauth_access_token_" + cookieName)
	// 	if err == nil && cookie.Value != "" {
	// 		return cookie.Value
	// 	}
	// case types.AuthenticationTypeCookie:
	// 	bearerToken := r.Header.Get("Authorization")
	// 	if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
	// 		return bearerToken[7:]
	// 	}
	// }
	cookie, err := r.Cookie("__goauth_access_token_" + cookieName)
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
		return bearerToken[7:]
	}
	return ""
}
