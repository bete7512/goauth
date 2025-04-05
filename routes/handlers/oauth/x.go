package oauthhandlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/types"
	"github.com/bete7512/goauth/utils"
	"golang.org/x/oauth2"
)

type TwitterOauth struct {
	Auth *types.Auth
}

func NewTwitterOauth(auth *types.Auth) *TwitterOauth {
	return &TwitterOauth{
		Auth: auth,
	}
}

// TwitterUserInfo represents the user information returned by Twitter
type TwitterUserInfo struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Username        string `json:"username"`
	ProfileImageURL string `json:"profile_image_url"`
	Email           string `json:"email,omitempty"` // Only available if email scope is granted
}

// getTwitterOAuthConfig creates the OAuth2 config for Twitter
func (t *TwitterOauth) getTwitterOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     t.Auth.Config.Providers.Twitter.ClientID,
		ClientSecret: t.Auth.Config.Providers.Twitter.ClientSecret,
		RedirectURL:  t.Auth.Config.Providers.Twitter.RedirectURL,
		Scopes: []string{
			"users.read",
			"tweet.read",
			"email", // To get user's email
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://twitter.com/i/oauth2/authorize",
			TokenURL: "https://api.twitter.com/2/oauth2/token",
		},
	}
}

// SignIn initiates the Twitter OAuth flow
func (t *TwitterOauth) SignIn(w http.ResponseWriter, r *http.Request) {
	config := t.getTwitterOAuthConfig()

	// Generate a random state for CSRF protection
	state, err := t.Auth.TokenManager.GenerateRandomToken(32)
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

	// Generate PKCE code challenge (Twitter OAuth 2.0 requires PKCE)
	codeVerifier, err := t.Auth.TokenManager.GenerateRandomToken(64)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to generate code verifier",
			err,
		)
		return
	}

	// Store code verifier in a cookie
	codeVerifierCookie := &http.Cookie{
		Name:     "code_verifier",
		Value:    codeVerifier,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(time.Hour.Seconds()),
	}
	http.SetCookie(w, codeVerifierCookie)

	// Create code challenge for PKCE
	codeChallenge, err := utils.GeneratePKCECodeChallenge(codeVerifier)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to generate code challenge",
			err,
		)
		return
	}

	// Redirect user to Twitter's consent page with PKCE
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	url := config.AuthCodeURL(state, opts...)
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
			nil,
		)
		return
	}

	// Get code verifier from cookie for PKCE
	codeVerifierCookie, err := r.Cookie("code_verifier")
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusBadRequest,
			"Code verifier cookie not found",
			err,
		)
		return
	}

	// Exchange the authorization code for a token with PKCE
	code := r.FormValue("code")
	config := t.getTwitterOAuthConfig()

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", codeVerifierCookie.Value),
	}
	token, err := config.Exchange(context.Background(), code, opts...)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to exchange token: "+err.Error(),
			err,
		)
		return
	}

	// Get user info from Twitter
	userInfo, err := t.getUserInfo(token.AccessToken)
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
	// Note: Twitter might not always provide an email
	user := models.User{
		Email:      userInfo.Email, // This might be empty
		FirstName:  userInfo.Name,
		LastName:   "", // Twitter doesn't provide separate first/last name
		SigninVia:  "twitter",
		ProviderId: &userInfo.ID,
		Avatar:     &userInfo.ProfileImageURL,
	}

	// Handle the case where email is not provided
	if userInfo.Email == "" {
		// Option 1: Generate a placeholder email using the Twitter username
		user.Email = fmt.Sprintf("%s@twitter.placeholder", userInfo.Username)
		
		// Option 2: You could redirect to a page asking for the email
		// This would need additional handling on the frontend
	}

	err = t.Auth.Repository.GetUserRepository().UpsertUserByEmail(&user)
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
	accessToken, refreshToken, err := t.Auth.TokenManager.GenerateTokens(&user)
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
	err = t.Auth.Repository.GetTokenRepository().SaveToken(user.ID, refreshToken, models.RefreshToken, t.Auth.Config.AuthConfig.Cookie.RefreshTokenTTL)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to save refresh token",
			err,
		)
		return
	}

	// Set the token in a cookie or return it in the response
	tokenCookie := &http.Cookie{
		Name:     t.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Path:     t.Auth.Config.AuthConfig.Cookie.Path,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(t.Auth.Config.AuthConfig.Cookie.AccessTokenTTL.Seconds()),
	}
	http.SetCookie(w, tokenCookie)

	// Redirect to the frontend
	http.Redirect(w, r, t.Auth.Config.FrontendURL, http.StatusTemporaryRedirect)
}

// getUserInfo fetches the user information from Twitter API
func (t *TwitterOauth) getUserInfo(accessToken string) (*TwitterUserInfo, error) {
	// Twitter v2 API endpoint for user info
	url := "https://api.twitter.com/2/users/me?user.fields=id,name,username,profile_image_url"
	
	// Include email field if available
	url += ",email"
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s", body)
	}

	// Twitter API wraps the user data in a "data" field
	var response struct {
		Data TwitterUserInfo `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return &response.Data, nil
}

