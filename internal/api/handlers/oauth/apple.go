package oauthRoutes

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bete7512/goauth/internal/services"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/dto"
	"golang.org/x/oauth2"
)

// ===== APPLE OAUTH HANDLER =====

type AppleOauth struct {
	Auth *config.Auth
}

func NewAppleOauth(auth *config.Auth) *AppleOauth {
	return &AppleOauth{
		Auth: auth,
	}
}

// AppleUserInfo represents the user information returned by Apple
type AppleUserInfo struct {
	ID    string `json:"sub"`
	Email string `json:"email"`
	Name  struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"name"`
}

// getAppleOAuthConfig creates the OAuth2 config for Apple
func (a *AppleOauth) getAppleOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.Auth.Config.Providers.Apple.ClientID,
		ClientSecret: a.Auth.Config.Providers.Apple.ClientSecret,
		RedirectURL:  a.Auth.Config.Providers.Apple.RedirectURL,
		Scopes: []string{
			"name",
			"email",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://appleid.apple.com/auth/authorize",
			TokenURL: "https://appleid.apple.com/auth/token",
		},
	}
}

// SignIn initiates the Apple OAuth flow
func (a *AppleOauth) SignIn(w http.ResponseWriter, r *http.Request) {
	// Create service instance
	service := services.NewAuthService(a.Auth)

	// Generate OAuth state using service
	stateResponse, err := service.GenerateOAuthState(r.Context(), dto.Apple)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to generate state",
			err,
		)
		return
	}

	// Get OAuth sign-in URL using service
	url, err := service.GetOAuthSignInURL(r.Context(), dto.Apple, stateResponse.State)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to generate sign-in URL",
			err,
		)
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

	// Apple OAuth uses a "response_mode" of "form_post"
	url = url + "&response_mode=form_post"
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback handles the OAuth callback from Apple
func (a *AppleOauth) Callback(w http.ResponseWriter, r *http.Request) {
	// Apple returns data via POST, so we need to parse the form
	if err := r.ParseForm(); err != nil {
		utils.RespondWithError(
			w,
			http.StatusBadRequest,
			"Failed to parse form data",
			err,
		)
		return
	}

	// Verify state to prevent CSRF
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusBadRequest,
			"State cookie not found",
			err,
		)
		return
	}

	if r.FormValue("state") != stateCookie.Value {
		utils.RespondWithError(
			w,
			http.StatusBadRequest,
			"Invalid state parameter",
			err,
		)
		return
	}

	// Create service instance
	service := services.NewAuthService(a.Auth)

	// Prepare callback request
	req := &dto.OAuthCallbackRequest{
		Provider: dto.Apple,
		Code:     r.FormValue("code"),
		State:    r.FormValue("state"),
	}

	// Handle OAuth callback using service
	response, err := service.HandleOAuthCallback(r.Context(), req)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"OAuth callback failed: "+err.Error(),
			err,
		)
		return
	}

	// Set authentication cookies if tokens are provided
	if response.Tokens != nil {
		// Set access token cookie
		accessTokenCookie := &http.Cookie{
			Name:     a.Auth.Config.AuthConfig.Cookie.Name,
			Value:    response.Tokens.AccessToken,
			Path:     a.Auth.Config.AuthConfig.Cookie.Path,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(a.Auth.Config.AuthConfig.JWT.AccessTokenTTL.Seconds()),
		}
		http.SetCookie(w, accessTokenCookie)

		// Set refresh token cookie
		refreshTokenCookie := &http.Cookie{
			Name:     "refresh_token",
			Value:    response.Tokens.RefreshToken,
			Path:     a.Auth.Config.AuthConfig.Cookie.Path,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(a.Auth.Config.AuthConfig.JWT.RefreshTokenTTL.Seconds()),
		}
		http.SetCookie(w, refreshTokenCookie)
	}

	// Clear the OAuth state cookie
	stateCookie = &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	http.SetCookie(w, stateCookie)

	// Redirect to the frontend
	http.Redirect(w, r, a.Auth.Config.App.FrontendURL, http.StatusTemporaryRedirect)
}

// extractUserInfoFromJWT extracts user information from Apple's ID token
func (a *AppleOauth) extractUserInfoFromJWT(idToken string) (AppleUserInfo, error) {
	// Split the JWT token
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return AppleUserInfo{}, fmt.Errorf("invalid JWT token format")
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return AppleUserInfo{}, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var userInfo AppleUserInfo
	if err := json.Unmarshal(payload, &userInfo); err != nil {
		return AppleUserInfo{}, fmt.Errorf("failed to parse user info: %w", err)
	}

	return userInfo, nil
}
