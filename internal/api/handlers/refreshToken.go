package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
)

// HandleRefreshToken handles token refresh
func (h *AuthHandler) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Call service
	response, err := h.authService.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, err.Error(), err)
		return
	}

	// Set new cookies
	// setAuthCookies(w, response.Tokens)

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Call service
	response, err := h.authService.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, err.Error(), err)
		return
	}

	// Set new cookies
	// setAuthCookies(w, response.Tokens)

	utils.RespondWithJSON(w, http.StatusOK, response)
}
