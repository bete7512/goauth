package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
)

// TODO: redo this logic
// CheckAvailability handles POST /check-availability
func (h *CoreHandler) CheckAvailability(w http.ResponseWriter, r *http.Request) {

	var req dto.CheckAvailabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, "INVALID_REQUEST_BODY", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, "INVALID_REQUEST_BODY", err.Error())
		return
	}

	if req.Email != "" {
		// Check email availability
		// available, err := h.CoreService.CheckAvailability(ctx, "email", req.Email)
		http_utils.RespondSuccess(w, dto.CheckAvailabilityResponse{
			Available: true,
			Field:     "email",
			Message:   "Email is available",
		}, nil)
		return
	}

	if req.Username != "" {
		// Check username availability
		http_utils.RespondSuccess(w, dto.CheckAvailabilityResponse{
			Available: true,
			Field:     "username",
			Message:   "Username is available",
		}, nil)
		return
	}

	if req.Phone != "" {
		// Check phone availability
		available, err := h.CoreService.CheckAvailability(r.Context(), &req)
		if err != nil {
			http_utils.RespondError(w, http.StatusBadRequest, "INVALID_REQUEST_BODY", err.Error())
			return
		}
		if available.Available {
			http_utils.RespondSuccess(w, dto.CheckAvailabilityResponse{
				Available: true,
				Field:     "phone",
				Message:   "Phone number is available",
			}, nil)
		} else {
			http_utils.RespondError(w, http.StatusBadRequest, "INVALID_REQUEST_BODY", "Phone number is already taken")
		}
		return
	}

	// respond ok
	http_utils.RespondSuccess(w, dto.CheckAvailabilityResponse{
		Available: false,
	}, nil)
	return

}
