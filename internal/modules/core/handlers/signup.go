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
		"ip_address":         r.RemoteAddr,                         // primary IP
		"forwarded_for":      r.Header.Get("X-Forwarded-For"),      // if behind proxy
		"user_agent":         r.UserAgent(),                        // browser/device info
		"referer":            r.Referer(),                          // where the request came from
		"host":               r.Host,                               // target host
		"timestamp":          time.Now(),                           // when request occurred
		"user_id":            r.Context().Value(types.UserIDKey),   // if logged in
		"request_id":         r.Header.Get("X-Request-ID"),         // unique request id
		"device_fingerprint": r.Header.Get("X-Device-Fingerprint"), // e.g., hash of browser + screen + timezone
		"headers":            r.Header,                             // all headers
		"cookies":            r.Cookies(),                          // all cookies
		"query_params":       r.URL.Query(),                        // all query params
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
		err := h.deps.Events.EmitAsync(ctx, types.EventSendEmailVerification, map[string]interface{}{
			"user": *response.User.ToUser(),
		})
		if err != nil {
			h.deps.Logger.Errorf("core: failed to send email verification: %v", err)
			return
		}
	}
	if h.deps.Config.Core.RequirePhoneVerification {
		err := h.deps.Events.EmitAsync(ctx, types.EventSendPhoneVerification, map[string]interface{}{
			"user": *response.User.ToUser(),
		})
		if err != nil {
			h.deps.Logger.Errorf("core: failed to send phone verification: %v", err)
			return
		}
	}

	if err := h.deps.Events.EmitAsync(ctx, types.EventAfterSignup, map[string]interface{}{
		"user":     *response.User.ToUser(),
		"metadata": metadata,
	}); err != nil {
		return
	}
	if !h.deps.Config.Core.RequireEmailVerification && !h.deps.Config.Core.RequirePhoneVerification {
		h.setSessionCookies(w, response)
		w.WriteHeader(http.StatusCreated)
		http_utils.RespondSuccess(w, response, nil)
		return
	}

	w.WriteHeader(http.StatusCreated)
	http_utils.RespondSuccess(w, response, nil)
}
