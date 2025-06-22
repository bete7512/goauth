package oauthRoutes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bete7512/goauth/config"
	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

type MicrosoftOauth struct {
	Auth *config.Auth
}

func NewMicrosoftOauth(auth *config.Auth) *MicrosoftOauth {
	return &MicrosoftOauth{
		Auth: auth,
	}
}

// MicrosoftUserInfo represents the user information returned by Microsoft
type MicrosoftUserInfo struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	GivenName         string `json:"givenName"`
	Surname           string `json:"surname"`
	Email             string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"` // Alternative for email
}

// getMicrosoftOAuthConfig creates the OAuth2 config for Microsoft
// getMicrosoftOAuthConfig creates the OAuth2 config for Microsoft
func (m *MicrosoftOauth) getMicrosoftOAuthConfig() *oauth2.Config {
	// If tenant ID is specified, use it
	if m.Auth.Config.Providers.Microsoft.TenantId != nil {
		return &oauth2.Config{
			ClientID:     m.Auth.Config.Providers.Microsoft.ClientID,
			ClientSecret: m.Auth.Config.Providers.Microsoft.ClientSecret,
			RedirectURL:  m.Auth.Config.Providers.Microsoft.RedirectURL,
			Scopes: []string{
				"User.Read",
			},
			Endpoint: microsoft.AzureADEndpoint(*m.Auth.Config.Providers.Microsoft.TenantId),
		}
	}

	// This fixes the "userAudience" configuration error
	return &oauth2.Config{
		ClientID:     m.Auth.Config.Providers.Microsoft.ClientID,
		ClientSecret: m.Auth.Config.Providers.Microsoft.ClientSecret,
		RedirectURL:  m.Auth.Config.Providers.Microsoft.RedirectURL,
		Scopes: []string{
			"User.Read",
		},
		// Use "consumers" endpoint instead of "common" for personal Microsoft accounts
		Endpoint: microsoft.AzureADEndpoint("consumers"),
	}
}

// SignIn initiates the Microsoft OAuth flow
func (m *MicrosoftOauth) SignIn(w http.ResponseWriter, r *http.Request) {
	config := m.getMicrosoftOAuthConfig()

	// Generate a random state for CSRF protection
	state, err := m.Auth.TokenManager.GenerateRandomToken(32)
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

	// Redirect user to Microsoft's consent page
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback handles the OAuth callback from Microsoft
// Callback handles the OAuth callback from Microsoft
func (m *MicrosoftOauth) Callback(w http.ResponseWriter, r *http.Request) {
	// Parse URL query parameters to ensure we can access them
	if err := r.ParseForm(); err != nil {
		utils.RespondWithError(
			w,
			http.StatusBadRequest,
			"Failed to parse request parameters",
			err,
		)
		return
	}

	// Check for error response from Microsoft
	if errorMsg := r.URL.Query().Get("error"); errorMsg != "" {
		errorDesc := r.URL.Query().Get("error_description")
		utils.RespondWithError(
			w,
			http.StatusBadRequest,
			fmt.Sprintf("OAuth error: %s - %s", errorMsg, errorDesc),
			fmt.Errorf("%s: %s", errorMsg, errorDesc),
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

	stateParam := r.URL.Query().Get("state")
	if stateParam == "" {
		utils.RespondWithError(
			w,
			http.StatusBadRequest,
			"State parameter missing from request",
			fmt.Errorf("missing state parameter"),
		)
		return
	}

	if stateParam != stateCookie.Value {
		utils.RespondWithError(
			w,
			http.StatusBadRequest,
			"Invalid state parameter",
			fmt.Errorf("state mismatch: expected %s, got %s", stateCookie.Value, stateParam),
		)
		return
	}

	// Get the authorization code from query parameters
	code := r.URL.Query().Get("code")
	if code == "" {
		utils.RespondWithError(
			w,
			http.StatusBadRequest,
			"Authorization code missing from request",
			fmt.Errorf("missing code parameter"),
		)
		return
	}

	// Exchange the authorization code for a token
	config := m.getMicrosoftOAuthConfig()

	// Create a context with timeout for the token exchange
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, err := config.Exchange(ctx, code)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to exchange token: "+err.Error(),
			err,
		)
		return
	}

	// Get user info from Microsoft
	userInfo, err := m.getUserInfo(token.AccessToken)
	if err != nil {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"Failed to get user info: "+err.Error(),
			err,
		)
		return
	}

	// Use userPrincipalName as email if mail is not available
	email := userInfo.Email
	if email == "" {
		email = userInfo.UserPrincipalName
	}

	if email == "" {
		utils.RespondWithError(
			w,
			http.StatusInternalServerError,
			"No email address found in user profile",
			fmt.Errorf("missing email in Microsoft profile"),
		)
		return
	}

	// Create or update user in your system
	user := models.User{
		Email: email,
		FirstName: func() string {
			if userInfo.GivenName != "" {
				return userInfo.GivenName
			}
			return userInfo.DisplayName
		}(),
		LastName:    userInfo.Surname,
		SignedUpVia: "microsoft",
		ProviderId:  &userInfo.ID,
		Avatar:      nil, // Microsoft Graph API requires additional requests for photo
	}

	err = m.Auth.Repository.GetUserRepository().UpsertUserByEmail(&user)
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
	accessToken, refreshToken, err := m.Auth.TokenManager.GenerateTokens(&user)
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
	err = m.Auth.Repository.GetTokenRepository().SaveToken(user.ID, refreshToken, models.RefreshToken, m.Auth.Config.AuthConfig.JWT.RefreshTokenTTL)
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
		Name:     m.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Path:     m.Auth.Config.AuthConfig.Cookie.Path,
		HttpOnly: m.Auth.Config.AuthConfig.Cookie.HttpOnly,
		Secure:   m.Auth.Config.AuthConfig.Cookie.Secure,
		SameSite: m.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   int(m.Auth.Config.AuthConfig.JWT.AccessTokenTTL.Seconds()),
	}
	http.SetCookie(w, tokenCookie)

	// Redirect to the frontend
	http.Redirect(w, r, m.Auth.Config.App.FrontendURL, http.StatusTemporaryRedirect)
}

// getUserInfo fetches the user information from Microsoft Graph API
func (m *MicrosoftOauth) getUserInfo(accessToken string) (*MicrosoftUserInfo, error) {
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
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

	var userInfo MicrosoftUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

