package routes

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/utils"
)

// HandleVerifyPhone handles phone verification
func (h *AuthHandler) HandleVerifyPhone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	// Get code from request body
	var req struct {
		PhoneNumber string `json:"phone_number" validate:"required"`
		Code        string `json:"code" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	if req.PhoneNumber == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Phone number is required", nil)
		return
	}

	if req.Code == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Verification code is required", nil)
		return
	}

	// Get user ID from authenticated request
	userID, err := h.authenticateRequest(r, h.Auth.Config.AuthConfig.Cookie.Name, h.Auth.Config.AuthConfig.JWT.Secret)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Unauthorized: "+err.Error(), nil)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", nil)
		return
	}

	// // Validate verification code
	// valid, _, err := h.Auth.Repository.GetTokenRepository().ValidateToken(req.Code, models.PhoneVerificationToken)
	// if err != nil || !valid {
	// 	utils.RespondWithError(w, http.StatusBadRequest, "Invalid or expired verification code", nil)
	// 	return
	// }

	// Update user phone verification status
	user.PhoneVerified = true
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to update user", nil)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Phone number verified successfully",
		"user": map[string]interface{}{
			"id":                    user.ID,
			"first_name":            user.FirstName,
			"last_name":             user.LastName,
			"email":                 user.Email,
			"phone_number_verified": user.PhoneVerified,
		},
	})
}
