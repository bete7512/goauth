package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

// SendVerificationEmail handles POST /send-verification-email
func (h *CoreHandler) SendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.SendVerificationEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	response, authErr := h.coreService.SendEmailVerification(ctx, req.Email)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, response, nil)
}

// ResendVerificationEmail handles POST /resend-verification-email
func (h *CoreHandler) ResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.SendVerificationEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	response, authErr := h.coreService.ResendEmailVerification(ctx, req.Email)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, response, nil)
}

// SendVerificationPhone handles POST /send-verification-phone
func (h *CoreHandler) SendVerificationPhone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.SendVerificationPhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	response, authErr := h.coreService.SendPhoneVerification(ctx, req.Phone)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, response, nil)
}

// ResendVerificationPhone handles POST /resend-verification-phone
func (h *CoreHandler) ResendVerificationPhone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.SendVerificationPhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	response, authErr := h.coreService.ResendPhoneVerification(ctx, req.Phone)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, response, nil)
}

// VerifyEmail handles GET /verify-email?token=xxx
func (h *CoreHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token := r.URL.Query().Get("token")
	if token == "" {
		h.redirectToFrontend(w, r, false, "Missing verification token")
		return
	}

	_, authErr := h.coreService.VerifyEmail(ctx, token)
	if authErr != nil {
		h.redirectToFrontend(w, r, false, authErr.Message)
		return
	}

	h.redirectToFrontend(w, r, true, "Email verified successfully")
}

// VerifyPhone handles POST /verify-phone
func (h *CoreHandler) VerifyPhone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.VerifyPhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	response, authErr := h.coreService.VerifyPhone(ctx, req.Code, req.Phone)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, response, nil)
}

// ForgotPassword handles POST /forgot-password
func (h *CoreHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	response, authErr := h.coreService.ForgotPassword(ctx, &req)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, response, nil)
}

// ResetPassword handles POST /reset-password
func (h *CoreHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	response, authErr := h.coreService.ResetPassword(ctx, &req)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, response, nil)
}

// redirectToFrontend redirects to the frontend verify email page.
func (h *CoreHandler) redirectToFrontend(w http.ResponseWriter, r *http.Request, success bool, message string) {
	frontendConfig := h.deps.Config.FrontendConfig
	if frontendConfig == nil {
		if success {
			http_utils.RespondSuccess(w, map[string]interface{}{
				"message": message,
			}, nil)
		} else {
			http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidToken), message)
		}
		return
	}

	redirectURL := frontendConfig.URL + frontendConfig.VerifyEmailCallbackPath

	params := url.Values{}
	if success {
		params.Add("status", "success")
	} else {
		params.Add("status", "error")
	}

	redirectURL += "?" + params.Encode()

	http.Redirect(w, r, redirectURL, http.StatusFound)
}
