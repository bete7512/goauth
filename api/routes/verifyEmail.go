package routes

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/schemas"
	"github.com/bete7512/goauth/utils"
	"gorm.io/gorm"
)

// HandleVerifyEmail verifies user's email
func (h *AuthHandler) HandleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var token, email string
	if r.Method == http.MethodGet {
		token = r.URL.Query().Get("token")
		email = r.URL.Query().Get("email")
	} else {
		var req schemas.VerifyEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error(), nil)
			return
		}
		token = req.Token
		email = req.Email
	}

	if token == "" || email == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Missing token or email", nil)
		return
	}

	// Get user by email
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.RespondWithError(w, http.StatusBadRequest, "User not found", err)
			return
		}
		utils.RespondWithError(w, http.StatusBadRequest, "Internal server error", err)
		return
	}

	if user == nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", nil)
		return
	}
	// Validate verification token
	valid, err := h.Auth.Repository.GetTokenRepository().ValidateTokenWithUserID(user.ID, token, models.EmailVerificationToken)
	if err != nil || !valid {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid or expired verification token", err)
		return
	}

	// Mark email as verified
	user.EmailVerified = true
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to verify email: "+err.Error(), err)
		return
	}

	// Invalidate verification token
	err = h.Auth.Repository.GetTokenRepository().InvalidateToken(user.ID, token, models.EmailVerificationToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to invalidate verification token: "+err.Error(), err)
		return
	}

	// Generate tokens if needed
	var response map[string]interface{}
	if r.Method == http.MethodPost {
		accessToken, refreshToken, err := h.Auth.TokenManager.GenerateTokens(user)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate tokens", err)
			return
		}

		// Save refresh token
		err = h.Auth.Repository.GetTokenRepository().SaveToken(user.ID, refreshToken, models.EmailVerificationToken, h.Auth.Config.AuthConfig.Cookie.RefreshTokenTTL)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save refresh token", err)
			return
		}

		// Set access token cookie
		http.SetCookie(w, &http.Cookie{
			Name:     h.Auth.Config.AuthConfig.Cookie.Name,
			Value:    accessToken,
			Expires:  time.Now().Add(h.Auth.Config.AuthConfig.Cookie.AccessTokenTTL),
			Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
			Path:     h.Auth.Config.AuthConfig.Cookie.Path,
			Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
			HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   h.Auth.Config.AuthConfig.Cookie.MaxAge,
		})

		response = map[string]interface{}{
			"message":       "Email verified successfully",
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		}
	} else {
		response = map[string]interface{}{
			"message": "Email verified successfully",
		}
	}

	// json.NewEncoder(w).Encode(response)
	err = utils.RespondWithJSON(w, http.StatusOK, response)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
		return
	}
}
