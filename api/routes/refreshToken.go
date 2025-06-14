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

	// Validate refresh token
	claims, err := h.Auth.TokenManager.ValidateToken(token)
	if err != nil {
		
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid refresh token", nil)
		return
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid refresh token claims", nil)
		return
	}

	valid, err := h.Auth.Repository.GetTokenRepository().ValidateTokenWithUserID(userID, token, models.RefreshToken)
	if err != nil || !valid {
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
	err = h.Auth.Repository.GetTokenRepository().SaveToken(user.ID, refreshToken, models.RefreshToken, h.Auth.Config.AuthConfig.Cookie.RefreshTokenTTL)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save refresh token", nil)
		return
	}

	// Clear cookie regardless of token validity
	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_access_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.Cookie.AccessTokenTTL),
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
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.Cookie.RefreshTokenTTL),
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
