package handlers

import (
	"net/http"
	"time"
)

// setAccessTokenCookie sets a secure access token cookie
func (h *AuthHandler) setAccessTokenCookie(w http.ResponseWriter, accessToken string) {
	cookie := &http.Cookie{
		Name:     "__goauth_access_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
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
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   int(h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL.Seconds()),
	}
	http.SetCookie(w, cookie)
}
func (h *AuthHandler) setCsrfTokenCookie(w http.ResponseWriter, csrfToken string) {
	cookie := &http.Cookie{
		Name:     "__goauth_csrf_token_" + h.Auth.Config.Security.CSRF.CookieConfig.Name,
		Value:    csrfToken,
		Expires:  time.Now().Add(h.Auth.Config.Security.CSRF.TokenTTL),
		Domain:   h.Auth.Config.Security.CSRF.CookieConfig.Domain,
		Path:     h.Auth.Config.Security.CSRF.CookieConfig.Path,
		Secure:   h.Auth.Config.Security.CSRF.CookieConfig.Secure,
		HttpOnly: h.Auth.Config.Security.CSRF.CookieConfig.HttpOnly,
		SameSite: h.Auth.Config.Security.CSRF.CookieConfig.SameSite,
		MaxAge:   int(h.Auth.Config.Security.CSRF.TokenTTL.Seconds()),
	}
	http.SetCookie(w, cookie)
}

func (h *AuthHandler) clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "__goauth_access_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour * 24),
		Path:     "/",
		HttpOnly: true,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   0,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "__goauth_refresh_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour * 24),
		Path:     "/",
		HttpOnly: true,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   0,
	})

}

// // Helper functions for cookie management
// func setAuthCookies(w http.ResponseWriter, tokens dto.TokenData) {
// 	// Set access token cookie
// 	http.SetCookie(w, &http.Cookie{
// 		Name:     "access_token",
// 		Value:    tokens.AccessToken,
// 		Path:     "/",
// 		HttpOnly: true,
// 		Secure:   true,
// 		SameSite: http.SameSiteStrictMode,
// 		MaxAge:   int(tokens.ExpiresAt.Unix()),
// 	})

// 	// Set refresh token cookie
// 	http.SetCookie(w, &http.Cookie{
// 		Name:     "refresh_token",
// 		Value:    tokens.RefreshToken,
// 		Path:     "/",
// 		HttpOnly: true,
// 		Secure:   true,
// 		SameSite: http.SameSiteStrictMode,
// 		MaxAge:   30 * 24 * 60 * 60, // 30 days
// 	})
// }

// func clearAuthCookies(w http.ResponseWriter) {
// 	http.SetCookie(w, &http.Cookie{
// 		Name:     "access_token",
// 		Value:    "",
// 		Path:     "/",
// 		HttpOnly: true,
// 		Secure:   true,
// 		SameSite: http.SameSiteStrictMode,
// 		MaxAge:   -1,
// 	})

// 	http.SetCookie(w, &http.Cookie{
// 		Name:     "refresh_token",
// 		Value:    "",
// 		Path:     "/",
// 		HttpOnly: true,
// 		Secure:   true,
// 		SameSite: http.SameSiteStrictMode,
// 		MaxAge:   -1,
// 	})
// }

// =============================================================================
// authenticateRequest extracts and validates the token from a request
// func (h *AuthHandler) authenticateRequest(r *http.Request, cookieName, jwtSecret string) (string, error) {
// 	token := h.extractToken(r, cookieName)
// 	if token == "" {
// 		return "", errors.New("no authentication token provided")
// 	}

// 	claims, err := h.Auth.TokenManager.ValidateJWTToken(token)
// 	if err != nil {
// 		return "", err
// 	}

// 	userID, ok := claims["user_id"].(string)
// 	if !ok {
// 		return "", errors.New("invalid token claims")
// 	}

// 	return userID, nil
// }

// func (h *AuthHandler) extractToken(r *http.Request, cookieName string) string {
// 	if cookieName != "" {
// 		cookie, err := r.Cookie("__goauth_access_token_" + cookieName)
// 		if err == nil && cookie.Value != "" {
// 			return cookie.Value
// 		}
// 	}
// 	// Check for bearer token (assuming it's enabled by default for testing)
// 	bearerToken := r.Header.Get("Authorization")
// 	if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
// 		return bearerToken[7:]
// 	}

// 	return ""
// }
