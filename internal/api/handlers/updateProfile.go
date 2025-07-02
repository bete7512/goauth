package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/schemas"
	"github.com/bete7512/goauth/internal/utils"
)

// HandleUpdateUser handles user profile updates
func (h *AuthRoutes) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Authenticate user
	userID, err := h.authenticateRequest(r, h.Auth.Config.AuthConfig.Cookie.Name, h.Auth.Config.AuthConfig.JWT.Secret)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized: "+err.Error(), nil)
		return
	}

	var req schemas.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), nil)
		return
	}

	// Get current user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "user not found", err)
		return
	}

	// Update fields
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}

	// Update user
	err = h.Auth.Repository.GetUserRepository().UpdateUser(r.Context(), user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to update user: "+err.Error(), err)
		return
	}

	// Prepare user response
	userResponse := schemas.UserResponse{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}

	err = utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"user":    userResponse,
		"message": "user updated successfully",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", err)
		return
	}
}
