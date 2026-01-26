package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

func (h *CoreHandler) Signup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req dto.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	if err := req.ValidatePassword(h.deps.Config.Security.PasswordPolicy); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	metadata := map[string]interface{}{
		"ip_address":         r.RemoteAddr,
		"forwarded_for":      r.Header.Get("X-Forwarded-For"),
		"user_agent":         r.UserAgent(),
		"referer":            r.Referer(),
		"host":               r.Host,
		"timestamp":          time.Now(),
		"user_id":            r.Context().Value(types.UserIDKey),
		"request_id":         r.Header.Get("X-Request-ID"),
		"device_fingerprint": r.Header.Get("X-Device-Fingerprint"),
		"headers":            r.Header,
		"cookies":            r.Cookies(),
		"query_params":       r.URL.Query(),
	}
	signupData := map[string]interface{}{
		"body":     req,
		"metadata": metadata,
	}

	if err := h.deps.Events.EmitSync(ctx, types.EventBeforeSignup, signupData); err != nil {
		http_utils.RespondError(w, http.StatusForbidden, string(types.ErrForbidden), "Signup blocked: "+err.Error())
		return
	}

	response, err := h.CoreService.Signup(ctx, &req)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	if h.deps.Config.Core.RequireEmailVerification {
		emitErr := h.deps.Events.EmitAsync(ctx, types.EventSendEmailVerification, map[string]interface{}{
			"user": *response.User.ToUser(),
		})
		if emitErr != nil {
			h.deps.Logger.Errorf("core: failed to send email verification: %v", emitErr)
		}
	}

	if h.deps.Config.Core.RequirePhoneVerification {
		emitErr := h.deps.Events.EmitAsync(ctx, types.EventSendPhoneVerification, map[string]interface{}{
			"user": *response.User.ToUser(),
		})
		if emitErr != nil {
			h.deps.Logger.Errorf("core: failed to send phone verification: %v", emitErr)
		}
	}

	if emitErr := h.deps.Events.EmitAsync(ctx, types.EventAfterSignup, map[string]interface{}{
		"user":     *response.User.ToUser(),
		"metadata": metadata,
	}); emitErr != nil {
		h.deps.Logger.Errorf("core: failed to emit after signup event: %v", emitErr)
	}

	// Note: Tokens are no longer generated on signup
	// User should login using session or stateless auth module after signup
	w.WriteHeader(http.StatusCreated)
	http_utils.RespondSuccess(w, response, nil)
}
