package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

// check email availability
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

	available, err := h.CoreService.CheckEmailAvailability(r.Context(), req.Email)
	if err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	http_utils.RespondSuccess(w, map[string]bool{"is_available": available}, nil)

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

	available, err := h.CoreService.CheckUsernameAvailability(r.Context(), req.Username)
	if err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	http_utils.RespondSuccess(w, map[string]bool{"is_available": available}, nil)
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

	available, err := h.CoreService.CheckPhoneAvailability(r.Context(), req.Phone)
	if err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	http_utils.RespondSuccess(w, map[string]bool{"is_available": available}, nil)
}
