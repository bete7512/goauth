package routes

import (
	"net/http"
	"time"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/utils"
)

// HandleRefreshToken handles token refresh
func (h *AuthHandler) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	token := h.extractToken(r, "___goauth_refresh_token_"+h.Auth.Config.AuthConfig.Cookie.Name)
	if token == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "No refresh token provided", nil)
		return
	}
	// deviceId := r.Header.Get("User-Agent")

	// Validate refresh token
	claims, err := h.Auth.TokenManager.ValidateJWTToken(token)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid refresh token", nil)
		return
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid refresh token claims", nil)
		return
	}

	tokenRecord, err := h.Auth.Repository.GetTokenRepository().GetTokenByUserID(userID, models.RefreshToken)
	if err != nil || tokenRecord == nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid or expired refresh token", nil)
		return
	}


	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "User not found", nil)
		return
	}

	// Check if user is active
	if !user.Active {
		utils.RespondWithError(w, http.StatusUnauthorized, "Account is deactivated", nil)
		return
	}

	// Generate new tokens
	accessToken, refreshToken, err := h.Auth.TokenManager.GenerateTokens(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate tokens", nil)
		return
	}

	err = h.Auth.Repository.GetTokenRepository().InvalidateToken(userID, token, models.RefreshToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to invalidate refresh token", nil)
		return
	}

	// Save new refresh token
	err = h.Auth.Repository.GetTokenRepository().SaveTokenWithDeviceId(user.ID, refreshToken, r.Header.Get("User-Agent"), models.RefreshToken, h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save refresh token", nil)
		return
	}

	// Clear cookie regardless of token validity
	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_access_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   h.Auth.Config.AuthConfig.Cookie.MaxAge,
	})
	// 		Name:     "___goauth_refresh_token_" + h.Auth.Config.CookieName,

	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_refresh_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    refreshToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   h.Auth.Config.AuthConfig.Cookie.MaxAge,
	})

	response := map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	err = utils.RespondWithJSON(w, http.StatusOK, response)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", nil)
		return
	}
}
