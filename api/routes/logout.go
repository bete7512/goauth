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
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	token := h.extractToken(r, h.Auth.Config.AuthConfig.Cookie.Name)
	if token == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "no authentication token provided", nil)
		return
	}
	claims, err := h.Auth.TokenManager.ValidateJWTToken(token)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "invalid authentication token", nil)
		return
	}

	refreshToken, err := h.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(r.Context(), claims["user_id"].(string), models.RefreshToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to get refresh token", nil)
		return
	}

	userID := claims["user_id"].(string)
	if h.Auth.Config.AuthConfig.Methods.EnableMultiSession {
		err = h.Auth.Repository.GetTokenRepository().RevokeToken(r.Context(), refreshToken.ID)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "failed to invalidate refresh tokens", nil)
			return
		}
	} else {
		err = h.Auth.Repository.GetTokenRepository().RevokeAllTokens(r.Context(), userID, models.RefreshToken)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "failed to invalidate refresh tokens", nil)
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
		"message": "successfully logged out",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", nil)
		return
	}
}
