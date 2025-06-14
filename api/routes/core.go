package routes

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/bete7512/goauth/types"
)

type AuthHandler struct {
	Auth *types.Auth
}

func (h *AuthHandler) WithHooks(route string, handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.Auth.HookManager != nil && h.Auth.HookManager.GetBeforeHook(route) != nil {
			if !h.Auth.HookManager.ExecuteBeforeHooks(route, w, r) {
				return
			}
		}
		handler(w, r)
	}
}

// validatePasswordPolicy validates a password against the configured policy
func (h *AuthHandler) validatePasswordPolicy(password string, policy types.PasswordPolicy) error {
	if len(password) < policy.MinLength {
		return fmt.Errorf("password must be at least %d characters long", policy.MinLength)
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if policy.RequireUpper && !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if policy.RequireLower && !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if policy.RequireNumber && !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if policy.RequireSpecial && !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// authenticateRequest extracts and validates the token from a request
func (h *AuthHandler) authenticateRequest(r *http.Request, cookieName, jwtSecret string) (string, error) {
	token := h.extractToken(r, cookieName)
	if token == "" {
		return "", errors.New("no authentication token provided")
	}

	claims, err := h.Auth.TokenManager.ValidateToken(token)
	if err != nil {
		return "", err
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	return userID, nil
}

func (h *AuthHandler) extractToken(r *http.Request, cookieName string) string {
	if cookieName != "" {
		cookie, err := r.Cookie("___goauth_access_token_" + cookieName)
		if err == nil && cookie.Value != "" {
			return cookie.Value
		}
	}
	if h.Auth.Config.AuthConfig.EnableBearerAuth {
		bearerToken := r.Header.Get("Authorization")
		if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
			return bearerToken[7:]
		}

	}

	return ""
}
