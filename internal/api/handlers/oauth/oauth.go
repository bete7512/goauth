package oauth_handler

import (
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
)

// SignIn initiates the OAuth flow for any provider
func (h *OAuthHandler) SignIn(provider dto.OAuthProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate OAuth state using service
		stateResponse, err := h.services.OAuthService.GenerateOAuthState(r.Context(), provider)
		if err != nil {
			utils.RespondError(w, err.StatusCode, err.Message, err.Error())
			return
		}

		// Get OAuth sign-in URL using service
		url, err := h.services.OAuthService.GetOAuthSignInURL(r.Context(), provider, stateResponse.State)
		if err != nil {
			utils.RespondError(w, err.StatusCode, err.Message, err.Error())
			return
		}

		// Store state in a cookie
		stateCookie := &http.Cookie{
			Name:     "oauth_state",
			Value:    stateResponse.State,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(time.Hour.Seconds()),
		}
		http.SetCookie(w, stateCookie)

		// Apple-specific: add response_mode=form_post
		if provider == dto.Apple {
			url = url + "&response_mode=form_post"
		}

		// Redirect user to provider's consent page
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

// Callback handles the OAuth callback for any provider
func (h *OAuthHandler) Callback(provider dto.OAuthProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Apple uses POST with form data, others use GET with query params
		if provider == dto.Apple {
			if err := r.ParseForm(); err != nil {
				utils.RespondError(w, http.StatusBadRequest, "Failed to parse form data", err.Error())
				return
			}
		}

		// Verify state to prevent CSRF
		stateCookie, err := r.Cookie("oauth_state")
		if err != nil {
			utils.RespondError(w, http.StatusBadRequest, "State cookie not found", err.Error())
			return
		}

		// Get state from request (works for both GET query params and POST form data)
		state := r.FormValue("state")
		if state != stateCookie.Value {
			utils.RespondError(w, http.StatusBadRequest, "Invalid state parameter", "")
			return
		}

		// Prepare callback request
		req := &dto.OAuthCallbackRequest{
			Provider: provider,
			Code:     r.FormValue("code"),
			State:    state,
		}

		// Handle OAuth callback using service
		response, err := h.services.OAuthService.HandleOAuthCallback(r.Context(), req)
		if err != nil {
			utils.RespondError(w, http.StatusInternalServerError, "OAuth callback failed: "+err.Error(), err.Error())
			return
		}

		// Set authentication cookies if tokens are provided
		if response.Tokens != nil {
			// h.common.SetAuthCookies(w, r, response.Tokens)
		}

		// Clear the OAuth state cookie
		// h.common.ClearStateCookie(w, r)

		// Redirect to the frontend
		http.Redirect(w, r, h.config.App.FrontendURL, http.StatusTemporaryRedirect)
	}
}
