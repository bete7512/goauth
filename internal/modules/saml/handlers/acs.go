package handlers

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/bete7512/goauth/internal/modules/saml/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

// maxResponseBytes caps the SAMLResponse form body.
const maxResponseBytes = 1 << 20

// ACS is the Assertion Consumer Service.
// POST /saml/{provider}/acs  (SAMLResponse, RelayState)
func (h *SAMLHandler) ACS(w http.ResponseWriter, r *http.Request) {
	provider := providerFromPath(r)
	if provider == "" {
		h.handleError(w, r, string(types.ErrSAMLProviderNotFound), "provider is required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxResponseBytes)
	if err := r.ParseForm(); err != nil {
		h.handleError(w, r, string(types.ErrSAMLInvalidResponse), "malformed form body")
		return
	}
	if r.PostForm.Get("SAMLResponse") == "" {
		h.handleError(w, r, string(types.ErrSAMLInvalidResponse), "SAMLResponse is required")
		return
	}

	// SP-initiated responses echo our request ID as RelayState, and the
	// browser that started the login carries the same ID in a cookie. A
	// response without RelayState is IdP-initiated and has no binding.
	relayState := r.PostForm.Get("RelayState")
	if relayState != "" {
		binding, err := r.Cookie(bindingCookiePrefix + provider)
		if err != nil || subtle.ConstantTimeCompare([]byte(binding.Value), []byte(relayState)) != 1 {
			h.handleError(w, r, string(types.ErrSAMLInvalidRequest), "browser continuation does not match")
			return
		}
		http.SetCookie(w, h.bindingCookie(provider, "", -1))
	}

	metadata := &types.RequestMetadata{
		IPAddress:    r.RemoteAddr,
		ForwardedFor: r.Header.Get("X-Forwarded-For"),
		UserAgent:    r.UserAgent(),
		Referer:      r.Referer(),
		Host:         r.Host,
		Timestamp:    time.Now(),
	}

	result, authErr := h.service.HandleACS(r.Context(), provider, relayState, r, metadata)
	if authErr != nil {
		h.handleError(w, r, string(authErr.Code), authErr.Message)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	// A redirect to a path on this server is a first-party page, such as
	// the admin console: cookies only, never tokens in the URL.
	if local, ok := http_utils.LocalRedirectPath(result.ClientRedirectURI); ok {
		http_utils.FinishLocalSignIn(w, r, h.deps.Config.Security, local, result.AccessToken, result.RefreshToken, len(result.Challenges) > 0)
		return
	}
	if len(result.Challenges) > 0 {
		http_utils.RespondSuccess(w, map[string]interface{}{"challenges": result.Challenges, "message": "Authentication challenge required"}, nil)
		return
	}

	authResponse := &dto.AuthResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
		TokenType:    "Bearer",
		IsNewUser:    result.IsNewUser,
		Provider:     result.Provider,
		User: &dto.UserDTO{
			ID:            result.User.ID,
			Email:         result.User.Email,
			Username:      result.User.Username,
			Name:          result.User.Name,
			FirstName:     result.User.FirstName,
			LastName:      result.User.LastName,
			Avatar:        result.User.Avatar,
			EmailVerified: result.User.EmailVerified,
			Active:        result.User.Active,
			CreatedAt:     result.User.CreatedAt,
			LastLoginAt:   result.User.LastLoginAt,
		},
	}

	redirectURL := result.ClientRedirectURI
	if redirectURL == "" {
		redirectURL = h.config.DefaultRedirectURL
	}
	if redirectURL != "" {
		if !h.isAllowedRedirectURL(redirectURL) {
			h.handleError(w, r, "invalid_redirect_url", "redirect URL is not allowed")
			return
		}
		http_utils.SetCredentialCookies(w, h.deps.Config.Security, result.AccessToken, result.RefreshToken)
		if h.deps.Config.Security.AuthMode == types.AuthModeCookie {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		h.redirectWithTokens(w, r, redirectURL, authResponse)
		return
	}

	http_utils.SetCredentialCookies(w, h.deps.Config.Security, result.AccessToken, result.RefreshToken)
	http_utils.RespondSuccess(w, authResponse, nil)
}

// handleError redirects to ErrorRedirectURL when configured, else answers JSON.
func (h *SAMLHandler) handleError(w http.ResponseWriter, r *http.Request, errorCode, errorDesc string) {
	if h.config.ErrorRedirectURL != "" {
		if errorURL, err := url.Parse(h.config.ErrorRedirectURL); err == nil {
			query := errorURL.Query()
			query.Set("error", errorCode)
			if errorDesc != "" {
				query.Set("error_description", errorDesc)
			}
			errorURL.RawQuery = query.Encode()
			http.Redirect(w, r, errorURL.String(), http.StatusFound)
			return
		}
	}
	statusCode := http.StatusBadRequest
	switch errorCode {
	case string(types.ErrSAMLSignupDisabled), string(types.ErrSAMLAccountLinkingDisabled):
		statusCode = http.StatusForbidden
	case string(types.ErrInternalError):
		statusCode = http.StatusInternalServerError
	}
	http_utils.RespondError(w, statusCode, errorCode, errorDesc)
}

// redirectWithTokens passes tokens in the URL fragment, which browsers never send to servers.
func (h *SAMLHandler) redirectWithTokens(w http.ResponseWriter, r *http.Request, redirectURL string, response *dto.AuthResponse) {
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		h.handleError(w, r, "invalid_redirect_url", "failed to parse redirect URL")
		return
	}
	fragment := url.Values{}
	fragment.Set("access_token", response.AccessToken)
	if response.RefreshToken != "" {
		fragment.Set("refresh_token", response.RefreshToken)
	}
	fragment.Set("token_type", "Bearer")
	fragment.Set("expires_in", fmt.Sprintf("%d", response.ExpiresIn))
	if response.IsNewUser {
		fragment.Set("is_new_user", "true")
	}
	parsed.Fragment = fragment.Encode()
	http.Redirect(w, r, parsed.String(), http.StatusFound)
}

// isAllowedRedirectURL accepts only the origins of DefaultRedirectURL,
// ErrorRedirectURL and FrontendConfig.URL, preventing open redirects.
func (h *SAMLHandler) isAllowedRedirectURL(redirectURL string) bool {
	parsed, err := url.Parse(redirectURL)
	if err != nil || parsed.Host == "" {
		return false
	}
	allowed := []string{h.config.DefaultRedirectURL, h.config.ErrorRedirectURL}
	if h.deps.Config.FrontendConfig != nil && h.deps.Config.FrontendConfig.URL != "" {
		allowed = append(allowed, h.deps.Config.FrontendConfig.URL)
	}
	for _, candidate := range allowed {
		if candidate == "" {
			continue
		}
		candidateURL, err := url.Parse(candidate)
		if err != nil {
			continue
		}
		if parsed.Scheme == candidateURL.Scheme && parsed.Host == candidateURL.Host {
			return true
		}
	}
	return false
}
