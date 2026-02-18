package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

func (h *CoreHandler) CheckAvailability(w http.ResponseWriter, r *http.Request) {
	var req dto.CheckAvailabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	resp, goauthErr := h.coreService.CheckAvailability(r.Context(), &req)
	if goauthErr != nil {
		http_utils.RespondError(w, goauthErr.StatusCode, string(goauthErr.Code), goauthErr.Message)
		return
	}

	http_utils.RespondSuccess(w, resp, nil)
}
