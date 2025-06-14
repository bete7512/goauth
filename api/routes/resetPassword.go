package routes

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/schemas"
	"github.com/bete7512/goauth/utils"
)

// HandleResetPassword handles password reset
func (h *AuthHandler) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var req schemas.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error(), nil)
		return
	}

	// Validate token
	valid, userID, err := h.Auth.Repository.GetTokenRepository().ValidateToken(req.Token, models.PasswordResetToken)
	if err != nil || !valid {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid or expired reset token", err)
		return
	}

	// Validate password against policy
	if err := h.validatePasswordPolicy(req.NewPassword, h.Auth.Config.PasswordPolicy); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if userID == nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User ID is nil", nil)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(*userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", err)
		return
	}

	// Hash new password
	hashedPassword, err := h.Auth.TokenManager.HashPassword(req.NewPassword)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to secure password: "+err.Error(), err)
		return
	}

	// Update password
	user.Password = hashedPassword
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to update password: "+err.Error(), err)
		return
	}

	// Invalidate token
	err = h.Auth.Repository.GetTokenRepository().InvalidateToken(user.ID, req.Token, models.PasswordResetToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to invalidate token: "+err.Error(), err)
		return
	}

	if userID == nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User ID is nil", nil)
		return
	}
	// Invalidate all refresh tokens for security
	err = h.Auth.Repository.GetTokenRepository().InvalidateAllTokens(*userID, models.RefreshToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to invalidate refresh tokens: "+err.Error(), err)
		return
	}

	// Clear cookie
	err = utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Password reset successfully. Please log in with your new password.",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
		return
	}
}
