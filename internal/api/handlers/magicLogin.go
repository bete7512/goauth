package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
)

// SendMagicLink handles magic link request
func (h *AuthHandler) SendMagicLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.MagicLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Call service
	if err := h.authService.SendMagicLink(r.Context(), &req); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send magic link", err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "magic link sent"})
}

// VerifyMagicLink handles magic link verification
func (h *AuthHandler) VerifyMagicLink(w http.ResponseWriter, r *http.Request) {

	var req dto.MagicLinkVerificationRequest
	if r.Method == http.MethodGet {
		email := r.URL.Query().Get("email")
		if email == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "email is required", nil)
			return
		}
		token := r.URL.Query().Get("token")
		if token == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "token is required", nil)
			return
		}
		req = dto.MagicLinkVerificationRequest{
			Token: token,
			Email: email,
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
			return
		}
	}

	req.Ip = r.RemoteAddr
	req.UserAgent = r.UserAgent()
	// req.DeviceId = r.Header.Get("X-Device-Id") // TODO: get device id from request
	// req.Location = r.Header.Get("X-Location")  // TODO: get location from request

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Call service
	response, err := h.authService.VerifyMagicLink(r.Context(), &req)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	// Set cookies
	setAuthCookies(w, response.Tokens)

	utils.RespondWithJSON(w, http.StatusOK, response)
}
