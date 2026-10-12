package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/stateless/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

func (h *StatelessHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.RefreshRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "invalid refresh request")
		return
	}
	token, transportErr := http_utils.RefreshCredential(r, h.deps.Config.Security, req.RefreshToken)
	if transportErr != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), transportErr.Error())
		return
	}
	req.RefreshToken = token

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	response, err := h.StatelessService.Refresh(ctx, &req)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	if len(response.Challenges) > 0 {
		http_utils.RespondSuccess(w, response, nil)
		return
	}
	if response.AccessToken == nil || response.RefreshToken == nil {
		http_utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to generate tokens")
		return
	}

	h.setTokenCookies(w, &response)
	http_utils.RespondSuccess(w, response, nil)
}
