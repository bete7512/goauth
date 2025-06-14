package routes

import (
	"net/http"
	"time"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/utils"
)

// HandleLogout handles user logout
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
	token := h.extractToken(r, h.Auth.Config.AuthConfig.Cookie.Name)
	if token == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "No authentication token provided", nil)
		return
	}
	claims, err := h.Auth.TokenManager.ValidateToken(token)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid authentication token", nil)
		return
	}
	userID := claims["user_id"].(string)
	if h.Auth.Config.AuthConfig.EnableMultiSession {
		err = h.Auth.Repository.GetTokenRepository().InvalidateToken(userID, token, models.RefreshToken)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to invalidate refresh tokens", nil)
			return
		}
	} else {
		err = h.Auth.Repository.GetTokenRepository().InvalidateAllTokens(userID, models.RefreshToken)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to invalidate refresh tokens", nil)
			return
		}
	}

	// Clear cookie regardless of token validity
	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_access_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_refresh_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   -1,
	})

	err = utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Successfully logged out",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", nil)
		return
	}
}
