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

	metadata := &types.RequestMetadata{
		IPAddress:         r.RemoteAddr,
		ForwardedFor:      r.Header.Get("X-Forwarded-For"),
		UserAgent:         r.UserAgent(),
		Referer:           r.Referer(),
		Host:              r.Host,
		Timestamp:         time.Now(),
		RequestID:         r.Header.Get("X-Request-ID"),
		DeviceFingerprint: r.Header.Get("X-Device-Fingerprint"),
	}

	if err := h.deps.Events.EmitSync(ctx, types.EventBeforeSignup, &types.BeforeHookData{
		Body:     req,
		Metadata: metadata,
	}); err != nil {
		http_utils.RespondError(w, http.StatusForbidden, string(types.ErrForbidden), "Signup blocked: "+err.Error())
		return
	}

	response, err := h.coreService.Signup(ctx, &req)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	user := response.User.ToUser()

	if h.deps.Config.Core.RequireEmailVerification {
		if _, authErr := h.coreService.SendEmailVerification(ctx, user.Email); authErr != nil {
			h.deps.Logger.Errorf("core: failed to send email verification: %v", authErr.Message)
		}
	}

	if h.deps.Config.Core.RequirePhoneVerification {
		if _, authErr := h.coreService.SendPhoneVerification(ctx, user.PhoneNumber); authErr != nil {
			h.deps.Logger.Errorf("core: failed to send phone verification: %v", authErr.Message)
		}
	}

	if emitErr := h.deps.Events.EmitAsync(ctx, types.EventAfterSignup, &types.UserEventData{
		User:     user,
		Metadata: metadata,
	}); emitErr != nil {
		h.deps.Logger.Errorf("core: failed to emit after signup event: %v", emitErr)
	}

	http_utils.RespondCreated(w, response, nil)
}
