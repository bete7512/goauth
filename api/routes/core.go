package routes

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bete7512/goauth/config"
)

type AuthHandler struct {
	*config.Auth
}

// authenticateRequest extracts and validates the token from a request
func (h *AuthHandler) authenticateRequest(r *http.Request, cookieName, jwtSecret string) (string, error) {
	token := h.extractToken(r, cookieName)
	if token == "" {
		return "", errors.New("no authentication token provided")
	}

	claims, err := h.Auth.TokenManager.ValidateJWTToken(token)
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
	// Check for bearer token (assuming it's enabled by default for testing)
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
		return bearerToken[7:]
	}

	return ""
}

// setAccessTokenCookie sets a secure access token cookie
func (h *AuthHandler) setAccessTokenCookie(w http.ResponseWriter, accessToken string) {
	cookie := &http.Cookie{
		Name:     "___goauth_access_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.Auth.Config.AuthConfig.JWT.AccessTokenTTL.Seconds()),
	}

	http.SetCookie(w, cookie)
}

func (h *AuthHandler) setRefreshTokenCookie(w http.ResponseWriter, refreshToken string) {
	cookie := &http.Cookie{
		Name:     "___goauth_refresh_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    refreshToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL.Seconds()),
	}
	http.SetCookie(w, cookie)
}
func (h *AuthHandler) setCsrfTokenCookie(w http.ResponseWriter, csrfToken string) {
	cookie := &http.Cookie{
		Name:  "___goauth_csrf_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value: csrfToken,
		// Expires:  time.Now().Add(h.Auth.Config.AuthConfig.CSRF.TTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: http.SameSiteStrictMode,
		// MaxAge:   int(h.Auth.Config.AuthConfig.CSRF.TTL.Seconds()),
	}
	http.SetCookie(w, cookie)
}
