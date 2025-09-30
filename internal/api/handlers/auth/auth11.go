package auth_handler

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/types"
)

// HandleRefreshToken handles token refresh
func (h *AuthHandler) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Call service
	response, err := h.services.AuthService.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	// Set new cookies
	// setAuthCookies(w, response.Tokens)

	utils.RespondSuccess(w, response.Tokens, "Token refreshed successfully")
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Call service
	response, err := h.services.AuthService.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	// Set new cookies
	// setAuthCookies(w, response.Tokens)

	utils.RespondSuccess(w, response.Tokens, "Token refreshed successfully")
}

// HandleResetPassword handles password reset
func (h *AuthHandler) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.ResetPasswordRequest
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
	if err := h.services.AuthService.ResetPassword(r.Context(), &req); err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	utils.RespondSuccess[any](w, nil, "password reset successful")
}

// ResetPassword handles password reset
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.ResetPasswordRequest
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
	if err := h.services.AuthService.ResetPassword(r.Context(), &req); err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	utils.RespondSuccess[any](w, nil, "password reset successful")
}



// SendMagicLink handles magic link request
func (h *AuthHandler) SendMagicLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.MagicLinkRequest
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
	if err := h.services.AuthService.SendMagicLink(r.Context(), &req); err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	utils.RespondSuccess[any](w, nil, "magic link sent")
}

// VerifyMagicLink handles magic link verification
func (h *AuthHandler) VerifyMagicLink(w http.ResponseWriter, r *http.Request) {

	var req dto.MagicLinkVerificationRequest
	if r.Method == http.MethodGet {
		email := r.URL.Query().Get("email")
		if email == "" {
			utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), "email is required")
			return
		}
		token := r.URL.Query().Get("token")
		if token == "" {
			utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), "token is required")
			return
		}
		req = dto.MagicLinkVerificationRequest{
			Token: token,
			Email: email,
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
			return
		}
	}

	req.Ip = r.RemoteAddr
	req.UserAgent = r.UserAgent()
	// req.DeviceId = r.Header.Get("X-Device-Id") // TODO: get device id from request
	// req.Location = r.Header.Get("X-Location")  // TODO: get location from request

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Call service
	response, err := h.services.AuthService.VerifyMagicLink(r.Context(), &req)
	if err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	// Set cookies
	// setAuthCookies(w, response.Tokens)

	utils.RespondSuccess(w, response, "magic link verified")
}
