package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
)

// HandleVerifyPhone handles phone verification
func (h *AuthHandler) HandleVerifyPhone(w http.ResponseWriter, r *http.Request) {
	var req dto.PhoneVerificationRequest
	if r.Method == http.MethodGet {
		// get token and phone number
		code := r.URL.Query().Get("code")
		phoneNumber := r.URL.Query().Get("phone_number")
		if code == "" || phoneNumber == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "code and phone number are required", nil)
			return
		}
		req = dto.PhoneVerificationRequest{
			Code:        code,
			PhoneNumber: phoneNumber,
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
			return
		}
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Call service
	if err := h.authService.VerifyPhone(r.Context(), &req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "phone verified successfully"})
}
