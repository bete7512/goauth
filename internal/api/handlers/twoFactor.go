package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
)

// HandleEnableTwoFactor handles enabling two-factor authentication
func (h *AuthHandler) HandleEnableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.EnableTwoFactorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	response, err := h.authService.EnableTwoFactor(r.Context(), userID, &req)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleVerifyTwoFactor handles two-factor authentication verification
func (h *AuthHandler) HandleVerifyTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.TwoFactorVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	if err := h.authService.VerifyTwoFactor(r.Context(), userID, &req); err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "two-factor verification successful"})
}

// HandleDisableTwoFactor handles disabling two-factor authentication
func (h *AuthHandler) HandleDisableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.DisableTwoFactorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	if err := h.authService.DisableTwoFactor(r.Context(), userID, &req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "two-factor authentication disabled"})
} 