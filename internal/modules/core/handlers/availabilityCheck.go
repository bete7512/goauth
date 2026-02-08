package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

func (h *CoreHandler) CheckEmailAvailability(w http.ResponseWriter, r *http.Request) {
	var req dto.CheckAvailabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.ValidateEmail(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	resp, goauthErr := h.coreService.CheckEmailAvailability(r.Context(), req.Email)
	if goauthErr != nil {
		http_utils.RespondError(w, goauthErr.StatusCode, string(goauthErr.Code), goauthErr.Message)
		return
	}

	http_utils.RespondSuccess(w, resp, nil)
}

func (h *CoreHandler) CheckUsernameAvailability(w http.ResponseWriter, r *http.Request) {
	var req dto.CheckAvailabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.ValidateUsername(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	resp, goauthErr := h.coreService.CheckUsernameAvailability(r.Context(), req.Username)
	if goauthErr != nil {
		http_utils.RespondError(w, goauthErr.StatusCode, string(goauthErr.Code), goauthErr.Message)
		return
	}

	http_utils.RespondSuccess(w, resp, nil)
}

func (h *CoreHandler) CheckPhoneAvailability(w http.ResponseWriter, r *http.Request) {
	var req dto.CheckAvailabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.ValidatePhone(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	resp, goauthErr := h.coreService.CheckPhoneAvailability(r.Context(), req.Phone)
	if goauthErr != nil {
		http_utils.RespondError(w, goauthErr.StatusCode, string(goauthErr.Code), goauthErr.Message)
		return
	}

	http_utils.RespondSuccess(w, resp, nil)
}
