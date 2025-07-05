package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
)

// HandleGetCSRFToken generates and returns a CSRF token for the authenticated user
func (h *AuthHandler) HandleGetCSRFToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	userID := r.Context().Value(config.UserIDKey).(string)

	// Use cache service if available
	if h.Auth.Cache != nil {
		// Try to get existing token from cache
		cacheKey := "csrf:" + userID

		// Check if we have a cached token
		if cachedValue, err := h.Auth.Cache.Get(r.Context(), cacheKey); err == nil {
			// Found cached token, return it
			if cachedToken, ok := cachedValue.(string); ok {
				if h.Auth.Config.Security.CSRF.CookieEnabled {
					h.setCsrfTokenCookie(w, cachedToken)
				}
				utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "CSRF token retrieved from cache", "token": cachedToken})
				return
			}
		}
	}

	// Call service to generate new token
	token, err := h.authService.GetCSRFToken(r.Context(), userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), nil)
		return
	}

	// Cache the new token if cache is available
	if h.Auth.Cache != nil {
		cacheKey := "csrf:" + userID
		// Cache token for the duration of CSRF token TTL
		h.Auth.Cache.Set(r.Context(), cacheKey, token, h.Auth.Config.Security.CSRF.TokenTTL)
	}

	if h.Auth.Config.Security.CSRF.CookieEnabled {
		h.setCsrfTokenCookie(w, token)
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "CSRF token generated", "token": token})
}
