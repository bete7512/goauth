package middlewares

import (
	"errors"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/pkg/config"
)

type Middleware struct {
	Auth *config.Auth
}

func NewMiddleware(auth *config.Auth) *Middleware {
	return &Middleware{
		Auth: auth,
	}
}

// getUserIdFromRequest extracts and validates the token from a request
func (m *Middleware) getUserIdFromRequest(r *http.Request, cookieName string) (string, error) {
	token := m.extractToken(r, cookieName)
	if token == "" {
		return "", errors.New("no authentication token provided")
	}

	claims, err := m.Auth.TokenManager.ValidateJWTToken(token)
	if err != nil {
		return "", err
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	return userID, nil
}

func (m *Middleware) extractToken(r *http.Request, cookieName string) string {
	switch m.Auth.Config.AuthConfig.Methods.Type {
	case config.AuthenticationTypeCookie:
		cookie, err := r.Cookie("__goauth_access_token_" + cookieName)
		if err == nil && cookie.Value != "" {
			return cookie.Value
		}
	case config.AuthenticationTypeBearer:
		bearerToken := r.Header.Get("Authorization")
		if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
			return bearerToken[7:]
		}
	}
	return ""
}
