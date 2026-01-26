package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/modules/stateless/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

func (h *StatelessHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.RefreshRequest

	// Try to get refresh token from request body first
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		// Try to get from cookie
		refreshTokenName := "goauth_refresh_" + h.deps.Config.Security.Session.Name
		cookie, err := r.Cookie(refreshTokenName)
		if err == nil && cookie.Value != "" {
			req.RefreshToken = cookie.Value
		}

		// Try to get from Authorization header
		if req.RefreshToken == "" {
			bearerToken := r.Header.Get("Authorization")
			if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
				req.RefreshToken = bearerToken[7:]
			}
		}
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	response, err := h.StatelessService.Refresh(ctx, &req)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	if response.AccessToken == nil || response.RefreshToken == nil {
		http_utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to generate tokens")
		return
	}

	h.setTokenCookies(w, &response)
	http_utils.RespondSuccess(w, response, nil)
}

