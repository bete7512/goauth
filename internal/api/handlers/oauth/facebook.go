package oauthRoutes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
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
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Name      string `json:"name"`
	Picture   struct {
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
	config := f.getFacebookOAuthConfig()

	// Generate a random state for CSRF protection
	state, err := f.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to generate state",
			err,
		)
		return
	}

	// Store state in a cookie
	stateCookie := &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(time.Hour.Seconds()),
	}
	http.SetCookie(w, stateCookie)

	// Redirect user to Facebook's consent page
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
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

	// Exchange the authorization code for a token
	code := r.FormValue("code")
	config := f.getFacebookOAuthConfig()

	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to exchange token: "+err.Error(),
			err,
		)
		return
	}

	// Get user info from Facebook
	userInfo, err := f.getUserInfo(token.AccessToken)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to get user info: "+err.Error(),
			err,
		)
		return
	}

	// Create or update user in your system
	avatarURL := userInfo.Picture.Data.URL
	user := types.User{
		Email:       userInfo.Email,
		FirstName:   userInfo.FirstName,
		LastName:    userInfo.LastName,
		SignedUpVia: "facebook",
		ProviderId:  &userInfo.ID,
		Avatar:      &avatarURL,
	}

	err = f.Auth.Repository.GetUserRepository().UpsertUserByEmail(r.Context(), &user)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to create/update user: "+err.Error(),
			err,
		)
		return
	}

	// Generate tokens
	accessToken, refreshToken, err := f.Auth.TokenManager.GenerateTokens(&user)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to generate authentication tokens",
			err,
		)
		return
	}

	// Save refresh token
	err = f.Auth.Repository.GetTokenRepository().SaveToken(r.Context(), user.ID, refreshToken, types.RefreshToken, f.Auth.Config.AuthConfig.JWT.RefreshTokenTTL)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to save refresh token",
			err,
		)
		return
	}

	// Set the token in a cookie
	tokenCookie := &http.Cookie{
		Name:     f.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Path:     f.Auth.Config.AuthConfig.Cookie.Path,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(f.Auth.Config.AuthConfig.JWT.AccessTokenTTL.Seconds()),
	}
	http.SetCookie(w, tokenCookie)

	// Redirect to the frontend
	http.Redirect(w, r, f.Auth.Config.App.FrontendURL, http.StatusTemporaryRedirect)
}

// getUserInfo fetches the user information from Facebook API
func (f *FacebookOauth) getUserInfo(accessToken string) (*FacebookUserInfo, error) {
	url := "https://graph.facebook.com/me?fields=id,name,email,first_name,last_name,picture&access_token=" + accessToken
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s", body)
	}

	var userInfo FacebookUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}
