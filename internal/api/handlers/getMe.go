package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/schemas"
	"github.com/bete7512/goauth/internal/utils"
)

// HandleGetUser returns the current user's profile
func (h *AuthRoutes) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	// Authenticate user
	userID, err := h.authenticateRequest(r, h.Auth.Config.AuthConfig.Cookie.Name, h.Auth.Config.AuthConfig.JWT.Secret)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Unauthorized: "+err.Error(), nil)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", nil)
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
	err = utils.RespondWithJSON(w, http.StatusOK, userResponse)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", nil)
		return
	}
}
