package auth_handler

import (
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// HandleGetCSRFToken generates and returns a CSRF token for the authenticated user
func (h *AuthHandler) HandleGetCSRFToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	userID := r.Context().Value(config.UserIDKey).(string)

	// Use cache service if available
	// if h.common.Cache != nil {
	// 	// Try to get existing token from cache
	// 	cacheKey := "csrf:" + userID

	// 	// Check if we have a cached token
	// 	if cachedValue, err := h.Auth.Cache.Get(r.Context(), cacheKey); err == nil {
	// 		// Found cached token, return it
	// 		if cachedToken, ok := cachedValue.(string); ok {
	// 			if h.Auth.Config.Security.CSRF.CookieEnabled {
	// 				h.setCsrfTokenCookie(w, cachedToken)
	// 			}
	// 			utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "CSRF token retrieved from cache", "token": cachedToken})
	// 			return
	// 		}
	// 	}
	// }

	// Call service to generate new token
	token, err := h.services.CSRFService.GetCSRFToken(r.Context(), userID)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), err.Error())
		return
	}

	// // Cache the new token if cache is available
	// if h.common.Cache != nil {
	// 	cacheKey := "csrf:" + userID
	// 	// Cache token for the duration of CSRF token TTL
	// 	h.common.Cache.Set(r.Context(), cacheKey, token, h.config.Security.CSRF.TokenTTL)
	// }

	if h.config.Security.CSRF.CookieEnabled {
		h.common.SetCsrfTokenCookie(w, token)
	}

	utils.RespondSuccess(w, token, "CSRF token generated")
}
