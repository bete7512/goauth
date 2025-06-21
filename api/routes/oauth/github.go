package oauthRoutes

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
	"golang.org/x/oauth2/github"
)

type GitHubOauth struct {
	Auth *types.Auth
}

func NewGitHubOauth(auth *types.Auth) *GitHubOauth {
	return &GitHubOauth{
		Auth: auth,
	}
}

// GitHubUserInfo represents the user information returned by GitHub
type GitHubUserInfo struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
	Bio       string `json:"bio"`
}

// getGitHubOAuthConfig creates the OAuth2 config for GitHub
func (g *GitHubOauth) getGitHubOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.Auth.Config.Providers.GitHub.ClientID,
		ClientSecret: g.Auth.Config.Providers.GitHub.ClientSecret,
		RedirectURL:  g.Auth.Config.Providers.GitHub.RedirectURL,
		Scopes: []string{
			"user:email",
			"read:user",
		},
		Endpoint: github.Endpoint,
	}
}

// SignIn initiates the GitHub OAuth flow
func (g *GitHubOauth) SignIn(w http.ResponseWriter, r *http.Request) {
	config := g.getGitHubOAuthConfig()

	// Generate a random state for CSRF protection
	state, err := g.Auth.TokenManager.GenerateRandomToken(32)
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

	// Redirect user to GitHub's consent page
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback handles the OAuth callback from GitHub
func (g *GitHubOauth) Callback(w http.ResponseWriter, r *http.Request) {
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
	config := g.getGitHubOAuthConfig()

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

	// Get user info from GitHub
	userInfo, err := g.getUserInfo(token.AccessToken)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to get user info: "+err.Error(),
			err,
		)
		return
	}

	// If email is private, fetch email separately
	if userInfo.Email == "" {
		email, err := g.getPrimaryEmail(token.AccessToken)
		if err != nil {
			utils.RespondWithError(
				w,
				http.StatusInternalServerError,
				"Failed to get user email: "+err.Error(),
				err,
			)
			return
		}
		userInfo.Email = email
	}

	// Create or update user in your system
	providerId := fmt.Sprintf("%d", userInfo.ID)
	user := models.User{
		Email: userInfo.Email,
		FirstName: func() string {
			if userInfo.Name != "" {
				// Try to split name into first and last
				return userInfo.Name
			}
			return userInfo.Login
		}(),
		LastName:   "", // GitHub doesn't provide separated name fields
		SignedUpVia:  "github",
		ProviderId: &providerId,
		Avatar:     &userInfo.AvatarURL,
	}

	err = g.Auth.Repository.GetUserRepository().UpsertUserByEmail(&user)
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
	accessToken, refreshToken, err := g.Auth.TokenManager.GenerateTokens(&user)
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
	err = g.Auth.Repository.GetTokenRepository().SaveToken(user.ID, refreshToken, models.RefreshToken, g.Auth.Config.AuthConfig.Cookie.RefreshTokenTTL)
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
		Name:     g.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Path:     g.Auth.Config.AuthConfig.Cookie.Path,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(g.Auth.Config.AuthConfig.Cookie.AccessTokenTTL.Seconds()),
	}
	http.SetCookie(w, tokenCookie)

	// Redirect to the frontend
	http.Redirect(w, r, g.Auth.Config.FrontendURL, http.StatusTemporaryRedirect)
}

// getUserInfo fetches the user information from GitHub API
func (g *GitHubOauth) getUserInfo(accessToken string) (*GitHubUserInfo, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

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

	var userInfo GitHubUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// getPrimaryEmail fetches the primary email from GitHub API
// GitHub may not return the email if it's set to private, so we need to fetch it separately
func (g *GitHubOauth) getPrimaryEmail(accessToken string) (string, error) {
	type EmailResponse struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get user emails: %s", body)
	}

	var emails []EmailResponse
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	// Find the primary email
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	// If no primary email is found, use the first verified one
	for _, email := range emails {
		if email.Verified {
			return email.Email, nil
		}
	}

	return "", fmt.Errorf("no verified email found")
}
