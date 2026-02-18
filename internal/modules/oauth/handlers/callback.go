package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/bete7512/goauth/internal/modules/oauth/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

// Callback handles the OAuth provider callback
// GET /oauth/{provider}/callback?code=...&state=...
func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract provider from path
	providerName := extractProviderFromPath(r)
	if providerName == "" {
		h.handleError(w, r, "invalid_request", "provider is required")
		return
	}

	// Check for provider error
	errorParam := r.URL.Query().Get("error")
	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		h.handleError(w, r, errorParam, errorDesc)
		return
	}

	// Get authorization code and state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		h.handleError(w, r, "invalid_request", "authorization code is required")
		return
	}

	if state == "" {
		h.handleError(w, r, "invalid_request", "state parameter is required")
		return
	}

	// Collect request metadata
	metadata := &types.RequestMetadata{
		IPAddress:    r.RemoteAddr,
		ForwardedFor: r.Header.Get("X-Forwarded-For"),
		UserAgent:    r.UserAgent(),
		Referer:      r.Referer(),
		Host:         r.Host,
		Timestamp:    time.Now(),
	}

	// Handle the callback
	result, authErr := h.service.HandleCallback(ctx, providerName, code, state, metadata)
	if authErr != nil {
		h.handleError(w, r, string(authErr.Code), authErr.Message)
		return
	}

	// Build response
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

	// Determine redirect URL
	// Priority: 1. Client-provided redirect URI, 2. Config default redirect URL
	redirectURL := result.ClientRedirectURI
	if redirectURL == "" {
		redirectURL = h.config.DefaultRedirectURL
	}

	if redirectURL != "" {
		// Redirect to frontend with tokens in URL fragment
		h.redirectWithTokens(w, r, redirectURL, authResponse)
		return
	}

	// No redirect URL - set cookies and return JSON
	h.setAuthCookies(w, r, result.AccessToken, result.RefreshToken)
	http_utils.RespondSuccess(w, authResponse, nil)
}

// handleError handles OAuth errors
func (h *OAuthHandler) handleError(w http.ResponseWriter, r *http.Request, errorCode, errorDesc string) {
	// Check if we should redirect to error URL
	if h.config.ErrorRedirectURL != "" {
		errorURL, err := url.Parse(h.config.ErrorRedirectURL)
		if err == nil {
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

	// Return JSON error
	statusCode := http.StatusBadRequest
	switch errorCode {
	case string(types.ErrOAuthInvalidState), string(types.ErrOAuthStateExpired), string(types.ErrOAuthStateUsed):
		statusCode = http.StatusBadRequest
	case string(types.ErrOAuthProviderError):
		statusCode = http.StatusBadGateway
	case string(types.ErrOAuthSignupDisabled):
		statusCode = http.StatusForbidden
	case string(types.ErrOAuthEmailExists):
		statusCode = http.StatusConflict
	}

	http_utils.RespondError(w, statusCode, errorCode, errorDesc)
}

// redirectWithTokens redirects to the frontend with tokens in URL fragment
// Fragment is used instead of query params for security (fragments aren't sent to server)
func (h *OAuthHandler) redirectWithTokens(w http.ResponseWriter, r *http.Request, redirectURL string, response *dto.AuthResponse) {
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		h.handleError(w, r, "invalid_redirect_url", "failed to parse redirect URL")
		return
	}

	// Build fragment with tokens
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

// setAuthCookies sets authentication cookies
func (h *OAuthHandler) setAuthCookies(w http.ResponseWriter, r *http.Request, accessToken, refreshToken string) {
	// Get security config for cookie settings
	secConfig := h.deps.Config.Security.Session

	// Access token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "goauth_access_token",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secConfig.Secure,
		SameSite: secConfig.SameSite,
		MaxAge:   int(secConfig.AccessTokenTTL.Seconds()),
	})

	// Refresh token cookie (if provided)
	if refreshToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "goauth_refresh_token",
			Value:    refreshToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   secConfig.Secure,
			SameSite: secConfig.SameSite,
			MaxAge:   int(secConfig.RefreshTokenTTL.Seconds()),
		})
	}
}
