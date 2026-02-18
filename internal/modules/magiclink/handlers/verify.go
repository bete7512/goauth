package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/bete7512/goauth/internal/modules/magiclink/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

func (h *MagicLinkHandler) Verify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token := r.URL.Query().Get("token")
	if token == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Missing token parameter")
		return
	}

	response, authErr := h.service.VerifyMagicLink(ctx, token)
	if authErr != nil {
		if h.config.CallbackURL != "" {
			h.redirectWithError(w, r, authErr.Message)
			return
		}
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	if h.config.CallbackURL != "" {
		h.redirectWithTokens(w, r, response.AccessToken, response.RefreshToken)
		return
	}

	h.setAuthCookies(w, response.AccessToken, response.RefreshToken)
	http_utils.RespondSuccess(w, response, nil)
}

func (h *MagicLinkHandler) VerifyByCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.MagicLinkVerifyByCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	response, authErr := h.service.VerifyByCode(ctx, &req)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	h.setAuthCookies(w, response.AccessToken, response.RefreshToken)
	http_utils.RespondSuccess(w, response, nil)
}

func (h *MagicLinkHandler) redirectWithTokens(w http.ResponseWriter, r *http.Request, accessToken, refreshToken *string) {
	callbackURL := h.config.CallbackURL

	params := url.Values{}
	if accessToken != nil {
		params.Set("access_token", *accessToken)
	}
	if refreshToken != nil {
		params.Set("refresh_token", *refreshToken)
	}

	// Use URL fragment (#) so tokens aren't sent to the server in subsequent requests
	redirectURL := fmt.Sprintf("%s#%s", callbackURL, params.Encode())
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *MagicLinkHandler) redirectWithError(w http.ResponseWriter, r *http.Request, message string) {
	callbackURL := h.config.CallbackURL

	params := url.Values{}
	params.Set("error", message)

	redirectURL := fmt.Sprintf("%s#%s", callbackURL, params.Encode())
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *MagicLinkHandler) setAuthCookies(w http.ResponseWriter, accessToken, refreshToken *string) {
	if accessToken == nil || refreshToken == nil {
		return
	}

	sessionCfg := h.deps.Config.Security.Session
	accessTokenName := "goauth_access_" + sessionCfg.Name
	http.SetCookie(w, &http.Cookie{
		Name:     accessTokenName,
		Value:    *accessToken,
		HttpOnly: sessionCfg.HttpOnly,
		Secure:   sessionCfg.Secure,
		SameSite: sessionCfg.SameSite,
		Path:     sessionCfg.Path,
		MaxAge:   sessionCfg.MaxAge,
	})

	refreshTokenName := "goauth_refresh_" + sessionCfg.Name
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenName,
		Value:    *refreshToken,
		HttpOnly: sessionCfg.HttpOnly,
		Secure:   sessionCfg.Secure,
		SameSite: sessionCfg.SameSite,
		Path:     sessionCfg.Path,
		MaxAge:   sessionCfg.MaxAge,
	})
}
