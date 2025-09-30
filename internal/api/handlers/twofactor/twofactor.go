package twofactor_handler

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/types"
)

// HandleEnableTwoFactor handles enabling two-factor authentication
func (h *TwoFactorHandler) HandleEnableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.EnableTwoFactorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	response, err := h.services.TwoFactorService.EnableTwoFactor(r.Context(), userID, &req)
	if err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	utils.RespondSuccess(w, response, "Two-factor authentication enabled successfully")
}

// HandleVerifyTwoFactorSetup handles two-factor authentication setup verification
func (h *TwoFactorHandler) HandleVerifyTwoFactorSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.VerifyTwoFactorSetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	if err := h.services.TwoFactorService.VerifyTwoFactorSetup(r.Context(), userID, &req); err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	utils.RespondSuccess[any](w, nil, "two-factor authentication enabled successfully")
}

// HandleVerifyTwoFactor handles two-factor authentication verification
func (h *TwoFactorHandler) HandleVerifyTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.TwoFactorVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	if err := h.services.TwoFactorService.VerifyTwoFactor(r.Context(), userID, &req); err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	utils.RespondSuccess[any](w, nil, "two-factor verification successful")
}

// HandleResendTwoFactorCode handles resending two-factor authentication code
func (h *TwoFactorHandler) HandleResendTwoFactorCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.ResendTwoFactorCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	if err := h.services.TwoFactorService.ResendTwoFactorCode(r.Context(), userID, &req); err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	utils.RespondSuccess[any](w, nil, "two-factor code resent successfully")
}

// HandleGetTwoFactorStatus handles getting two-factor authentication status
func (h *TwoFactorHandler) HandleGetTwoFactorStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	response, err := h.services.TwoFactorService.GetTwoFactorStatus(r.Context(), userID)
	if err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	utils.RespondSuccess(w, response, "two-factor authentication status retrieved successfully")
}

// HandleTwoFactorLogin handles two-factor authentication during login
func (h *TwoFactorHandler) HandleTwoFactorLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.TwoFactorLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Call service
	response, err := h.services.TwoFactorService.TwoFactorLogin(r.Context(), &req)
	if err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	// Set cookies
	// setAuthCookies(w, response.Tokens)

	utils.RespondSuccess(w, response, "two-factor authentication successful")
}

// HandleDisableTwoFactor handles disabling two-factor authentication
func (h *TwoFactorHandler) HandleDisableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.DisableTwoFactorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	if err := h.services.TwoFactorService.DisableTwoFactor(r.Context(), userID, &req); err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	utils.RespondSuccess[any](w, nil, "two-factor authentication disabled")
}
