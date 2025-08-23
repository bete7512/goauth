package oauthRoutes

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/services"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/dto"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

// ===== FACEBOOK OAUTH HANDLER =====

type FacebookOauth struct {
	Auth *config.Auth
}

func NewFacebookOauth(auth *config.Auth) *FacebookOauth {
	return &FacebookOauth{
		Auth: auth,
	}
}

// FacebookUserInfo represents the user information returned by Facebook
type FacebookUserInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture struct {
		Data struct {
			URL string `json:"url"`
		} `json:"data"`
	} `json:"picture"`
}

// getFacebookOAuthConfig creates the OAuth2 config for Facebook
func (f *FacebookOauth) getFacebookOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     f.Auth.Config.Providers.Facebook.ClientID,
		ClientSecret: f.Auth.Config.Providers.Facebook.ClientSecret,
		RedirectURL:  f.Auth.Config.Providers.Facebook.RedirectURL,
		Scopes: []string{
			"email",
			"public_profile",
		},
		Endpoint: facebook.Endpoint,
	}
}

// SignIn initiates the Facebook OAuth flow
func (f *FacebookOauth) SignIn(w http.ResponseWriter, r *http.Request) {
	// Create service instance
	service := services.NewAuthService(f.Auth)

	// Generate OAuth state using service
	stateResponse, err := service.GenerateOAuthState(r.Context(), dto.Facebook)
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
	url, err := service.GetOAuthSignInURL(r.Context(), dto.Facebook, stateResponse.State)
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

	// Redirect user to Facebook's consent page
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback handles the OAuth callback from Facebook
func (f *FacebookOauth) Callback(w http.ResponseWriter, r *http.Request) {
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
	service := services.NewAuthService(f.Auth)

	// Prepare callback request
	req := &dto.OAuthCallbackRequest{
		Provider: dto.Facebook,
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
			Name:     f.Auth.Config.AuthConfig.Cookie.Name,
			Value:    response.Tokens.AccessToken,
			Path:     f.Auth.Config.AuthConfig.Cookie.Path,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(f.Auth.Config.AuthConfig.JWT.AccessTokenTTL.Seconds()),
		}
		http.SetCookie(w, accessTokenCookie)

		// Set refresh token cookie
		refreshTokenCookie := &http.Cookie{
			Name:     "refresh_token",
			Value:    response.Tokens.RefreshToken,
			Path:     f.Auth.Config.AuthConfig.Cookie.Path,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(f.Auth.Config.AuthConfig.JWT.RefreshTokenTTL.Seconds()),
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
	http.Redirect(w, r, f.Auth.Config.App.FrontendURL, http.StatusTemporaryRedirect)
}

// getUserInfo gets user information from Facebook
func (f *FacebookOauth) getUserInfo(accessToken string) (*FacebookUserInfo, error) {
	url := "https://graph.facebook.com/me?fields=id,name,email,picture&access_token=" + accessToken
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: %s", string(body))
	}

	var userInfo FacebookUserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return nil, err
	}

	return &userInfo, nil
}
