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
	"golang.org/x/oauth2/linkedin"
)

type LinkedInOauth struct {
	Auth *types.Auth
}

func NewLinkedInOauth(auth *types.Auth) *LinkedInOauth {
	return &LinkedInOauth{
		Auth: auth,
	}
}

// LinkedInUserInfo represents the user information returned by LinkedIn
type LinkedInUserInfo struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	FirstName      string `json:"localizedFirstName"`
	LastName       string `json:"localizedLastName"`
	ProfilePicture struct {
		DisplayImage struct {
			Elements []struct {
				Identifiers []struct {
					Identifier string `json:"identifier"`
				} `json:"identifiers"`
			} `json:"elements"`
		} `json:"displayImage~"`
	} `json:"profilePicture"`
}

// getLinkedInOAuthConfig creates the OAuth2 config for LinkedIn
func (l *LinkedInOauth) getLinkedInOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     l.Auth.Config.Providers.LinkedIn.ClientID,
		ClientSecret: l.Auth.Config.Providers.LinkedIn.ClientSecret,
		RedirectURL:  l.Auth.Config.Providers.LinkedIn.RedirectURL,
		Scopes: []string{
			"r_liteprofile",
			"r_emailaddress",
		},
		Endpoint: linkedin.Endpoint,
	}
}

// SignIn initiates the LinkedIn OAuth flow
func (l *LinkedInOauth) SignIn(w http.ResponseWriter, r *http.Request) {
	config := l.getLinkedInOAuthConfig()

	// Generate a random state for CSRF protection
	state, err := l.Auth.TokenManager.GenerateRandomToken(32)
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

	// Redirect user to LinkedIn's consent page
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback handles the OAuth callback from LinkedIn
func (l *LinkedInOauth) Callback(w http.ResponseWriter, r *http.Request) {
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

	if code == "" {
		code = r.URL.Query().Get("code")

	}
	config := l.getLinkedInOAuthConfig()

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

	// Get user info from LinkedIn
	userInfo, err := l.getUserInfo(token.AccessToken)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to get user info: "+err.Error(),
			err,
		)
		return
	}

	// Get email separately (LinkedIn requires a separate API call)
	email, err := l.getUserEmail(token.AccessToken)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to get user email: "+err.Error(),
			err,
		)
		return
	}

	// Get profile picture URL
	var avatarURL string
	if len(userInfo.ProfilePicture.DisplayImage.Elements) > 0 &&
		len(userInfo.ProfilePicture.DisplayImage.Elements[0].Identifiers) > 0 {
		avatarURL = userInfo.ProfilePicture.DisplayImage.Elements[0].Identifiers[0].Identifier
	}

	// Create or update user in your system
	user := models.User{
		Email:      email,
		FirstName:  userInfo.FirstName,
		LastName:   userInfo.LastName,
		SigninVia:  "linkedin",
		ProviderId: &userInfo.ID,
		Avatar:     &avatarURL,
	}

	err = l.Auth.Repository.GetUserRepository().UpsertUserByEmail(&user)
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
	accessToken, refreshToken, err := l.Auth.TokenManager.GenerateTokens(&user)
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
	err = l.Auth.Repository.GetTokenRepository().SaveToken(user.ID, refreshToken, models.RefreshToken, l.Auth.Config.AuthConfig.Cookie.RefreshTokenTTL)
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
		Name:     l.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Path:     l.Auth.Config.AuthConfig.Cookie.Path,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(l.Auth.Config.AuthConfig.Cookie.AccessTokenTTL.Seconds()),
	}
	http.SetCookie(w, tokenCookie)

	// Redirect to the frontend
	http.Redirect(w, r, l.Auth.Config.FrontendURL, http.StatusTemporaryRedirect)
}

// getUserInfo fetches the user profile information from LinkedIn API
func (l *LinkedInOauth) getUserInfo(accessToken string) (*LinkedInUserInfo, error) {
	// LinkedIn requires a specific format for user profile requests
	url := "https://api.linkedin.com/v2/me?projection=(id,localizedFirstName,localizedLastName,profilePicture(displayImage~:playableStreams))"
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

	var userInfo LinkedInUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// getUserEmail fetches the user's email from LinkedIn API
func (l *LinkedInOauth) getUserEmail(accessToken string) (string, error) {
	url := "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get user email: %s", body)
	}

	// Parse LinkedIn's email response structure
	var result struct {
		Elements []struct {
			Handle struct {
				EmailAddress string `json:"emailAddress"`
			} `json:"handle~"`
		} `json:"elements"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Elements) == 0 {
		return "", fmt.Errorf("no email found")
	}

	return result.Elements[0].Handle.EmailAddress, nil
}

// {"status":500,"message":"Failed to exchange token: oauth2: \"invalid_request\" \"A required parameter \\\"code\\\" is missing\"","error":"oauth2: \"invalid_request\" \"A required parameter \\\"code\\\" is missing\""}
 