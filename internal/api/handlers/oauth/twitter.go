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
)

type TwitterOauth struct {
	Auth *config.Auth
}

func NewTwitterOauth(auth *config.Auth) *TwitterOauth {
	return &TwitterOauth{
		Auth: auth,
	}
}

// TwitterUserInfo represents the user information returned by Twitter
type TwitterUserInfo struct {
	ID              string `json:"id"`
	Username        string `json:"username"`
	Name            string `json:"name"`
	Email           string `json:"email"`
	ProfileImageURL string `json:"profile_image_url"`
	Verified        bool   `json:"verified"`
	Protected       bool   `json:"protected"`
	CreatedAt       string `json:"created_at"`
}

// getTwitterOAuthConfig creates the OAuth2 config for Twitter
func (t *TwitterOauth) getTwitterOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     t.Auth.Config.Providers.Twitter.ClientID,
		ClientSecret: t.Auth.Config.Providers.Twitter.ClientSecret,
		RedirectURL:  t.Auth.Config.Providers.Twitter.RedirectURL,
		Scopes: []string{
			"tweet.read",
			"users.read",
			"offline.access",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://twitter.com/i/oauth2/authorize",
			TokenURL: "https://api.twitter.com/2/oauth2/token",
		},
	}
}

// SignIn initiates the Twitter OAuth flow
func (t *TwitterOauth) SignIn(w http.ResponseWriter, r *http.Request) {
	// Create service instance
	service := services.NewAuthService(t.Auth)

	// Generate OAuth state using service
	stateResponse, err := service.GenerateOAuthState(r.Context(), dto.Twitter)
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
	url, err := service.GetOAuthSignInURL(r.Context(), dto.Twitter, stateResponse.State)
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

	// Redirect user to Twitter's consent page
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback handles the OAuth callback from Twitter
func (t *TwitterOauth) Callback(w http.ResponseWriter, r *http.Request) {
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
	service := services.NewAuthService(t.Auth)

	// Prepare callback request
	req := &dto.OAuthCallbackRequest{
		Provider: dto.Twitter,
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
			Name:     t.Auth.Config.AuthConfig.Cookie.Name,
			Value:    response.Tokens.AccessToken,
			Path:     t.Auth.Config.AuthConfig.Cookie.Path,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(t.Auth.Config.AuthConfig.JWT.AccessTokenTTL.Seconds()),
		}
		http.SetCookie(w, accessTokenCookie)

		// Set refresh token cookie
		refreshTokenCookie := &http.Cookie{
			Name:     "refresh_token",
			Value:    response.Tokens.RefreshToken,
			Path:     t.Auth.Config.AuthConfig.Cookie.Path,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(t.Auth.Config.AuthConfig.JWT.RefreshTokenTTL.Seconds()),
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
	http.Redirect(w, r, t.Auth.Config.App.FrontendURL, http.StatusTemporaryRedirect)
}

// getUserInfo gets user information from Twitter
func (t *TwitterOauth) getUserInfo(accessToken string) (*TwitterUserInfo, error) {
	url := "https://api.twitter.com/2/users/me?user.fields=id,username,name,email,profile_image_url,verified,protected,created_at"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

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

	// Twitter API v2 returns data in a wrapper object
	var response struct {
		Data TwitterUserInfo `json:"data"`
	}

	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return &response.Data, nil
}
