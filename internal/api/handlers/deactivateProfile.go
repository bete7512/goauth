package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/schemas"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

// HandleDeactivateUser handles user account deactivation
func (h *AuthRoutes) HandleDeactivateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Authenticate user
	userID, err := h.authenticateRequest(r, h.Auth.Config.AuthConfig.Cookie.Name, h.Auth.Config.AuthConfig.JWT.Secret)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized: "+err.Error(), nil)
		return
	}

	var req schemas.DeactivateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), nil)
		return
	}

	// Get current user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.RespondWithError(w, http.StatusBadRequest, "user not found", err)
			return
		}
		utils.RespondWithError(w, http.StatusBadRequest, "internal server error", err)
		return
	}

	// Verify password
	err = h.Auth.TokenManager.ValidatePassword(user.Password, req.Password)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "password is incorrect", err)
		return
	}

	// Deactivate user
	active := false
	user.Active = &active
	err = h.Auth.Repository.GetUserRepository().UpdateUser(r.Context(), user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to deactivate account: "+err.Error(), err)
		return
	}

	// Invalidate all refresh tokens
	err = h.Auth.Repository.GetTokenRepository().RevokeAllTokens(r.Context(), userID, models.RefreshToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to invalidate refresh tokens: "+err.Error(), err)
		return
	}
	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	// json.NewEncoder(w).Encode(map[string]string{
	// 	"message": "Account deactivated successfully",
	// })

	err = utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "account deactivated successfully",
	})

	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", err)
		return
	}
}
