package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/modules/passkeys/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/passkeys/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type PasskeyHandler struct {
	service services.PasskeyService
	deps    config.ModuleDependencies
}

func NewPasskeyHandler(service services.PasskeyService, deps config.ModuleDependencies) *PasskeyHandler {
	return &PasskeyHandler{service: service, deps: deps}
}

func (h *PasskeyHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user id not found in request")
		return
	}
	resp, authErr := h.service.BeginRegistration(r.Context(), userID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}
	http_utils.RespondSuccess(w, resp, nil)
}

func (h *PasskeyHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user id not found in request")
		return
	}
	var req dto.FinishRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "invalid request body")
		return
	}
	resp, authErr := h.service.FinishRegistration(r.Context(), userID, &req)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}
	http_utils.RespondCreated(w, resp, nil)
}

func (h *PasskeyHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	resp, authErr := h.service.BeginLogin(r.Context())
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}
	http_utils.RespondSuccess(w, resp, nil)
}

func (h *PasskeyHandler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	var req dto.FinishLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "invalid request body")
		return
	}
	resp, authErr := h.service.FinishLogin(r.Context(), &req)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}
	if resp.AccessToken != nil && resp.RefreshToken != nil {
		http_utils.SetCredentialCookies(w, h.deps.Config.Security, *resp.AccessToken, *resp.RefreshToken)
	}
	http_utils.RespondSuccess(w, resp, nil)
}

func (h *PasskeyHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user id not found in request")
		return
	}
	items, authErr := h.service.ListCredentials(r.Context(), userID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}
	http_utils.RespondSuccess(w, items, nil)
}

func (h *PasskeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user id not found in request")
		return
	}
	credentialID := pathTail(r.URL.Path)
	if credentialID == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), "missing passkey id")
		return
	}
	if authErr := h.service.DeleteCredential(r.Context(), userID, credentialID); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}
	http_utils.RespondSuccess[any](w, nil, nil)
}

func (h *PasskeyHandler) Rename(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user id not found in request")
		return
	}
	credentialID := pathTail(r.URL.Path)
	if credentialID == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), "missing passkey id")
		return
	}
	var req dto.RenameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), "name is required")
		return
	}
	if authErr := h.service.RenameCredential(r.Context(), userID, credentialID, req.Name); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}
	http_utils.RespondSuccess[any](w, nil, nil)
}

// pathTail returns the last path segment from routes like "/api/v1/passkeys/{id}".
// This module doesn't rely on a specific router — adapters strip the BasePath,
// so we just grab the trailing segment.
func pathTail(p string) string {
	p = strings.TrimRight(p, "/")
	idx := strings.LastIndex(p, "/")
	if idx < 0 {
		return ""
	}
	return p[idx+1:]
}
