package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/utils"
)

// HandleResendVerificationEmail resends verification email

func (h *AuthHandler) SendMagicLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error(), nil)
		return
	}
	// Check if user exists
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", err)
		return
	}
	if user == nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", nil)
		return
	}
	// Generate 1 link token
	magicLinkToken, err := h.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate magic link token", err)
		return
	}
	// Save magic link token (valid for 10 minutes)
	err = h.Auth.Repository.GetTokenRepository().SaveToken(r.Context(), user.ID, magicLinkToken, models.MakicLinkToken, 10*time.Minute)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save magic link token", err)
		return
	}
	// Send magic link email
	if h.Auth.Config.Email.Sender.CustomSender != nil {
		magicLinkURL := fmt.Sprintf("%s?token=%s&email=%s",
			h.Auth.Config.App.FrontendURL,
			magicLinkToken,
			user.Email)
		err = h.Auth.Config.Email.Sender.CustomSender.SendMagicLinkEmail(r.Context(), *user, magicLinkURL)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send magic link email", err)
			return
		}
	}

	err = utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Magic link sent successfully",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
		return
	}
}

// HandleVerifyMagicLink verifies the magic link token
func (h *AuthHandler) HandleVerifyMagicLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
	var req struct {
		Email string `json:"email"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error(), nil)
		return
	}

	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", err)
		return
	}
	if user == nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", nil)
		return
	}
	// valid, userID, err := h.Auth.Repository.GetTokenRepository().ValidateToken(req.Token, models.MakicLinkToken)
	// if err != nil || !valid || userID == nil {
	// 	utils.RespondWithError(w, http.StatusBadRequest, "Invalid or expired magic link token", err)
	// 	return
	// }
	// // Get user
	// user, err := h.Auth.Repository.GetUserRepository().GetUserByID(*userID)
	// if err != nil {
	// 	if errors.Is(err, gorm.ErrRecordNotFound) {
	// 		utils.RespondWithError(w, http.StatusBadRequest, "User not found", err)
	// 		return
	// 	}
	// 	utils.RespondWithError(w, http.StatusBadRequest, "Internal server error", err)
	// 	return
	// }
	// Generate access and refresh tokens
	accessToken, refreshToken, err := h.Auth.TokenManager.GenerateTokens(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate tokens", err)
		return
	}
	// Save refresh token
	err = h.Auth.Repository.GetTokenRepository().SaveToken(r.Context(), user.ID, refreshToken, models.RefreshToken, h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save refresh token", err)
		return
	}
	// Set access token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: true,
	})
	// Send response
	err = utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Login successful",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
		return
	}
}
