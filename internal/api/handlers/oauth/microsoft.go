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
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
	JobTitle          string `json:"jobTitle"`
	MobilePhone       string `json:"mobilePhone"`
	OfficeLocation    string `json:"officeLocation"`
	PreferredLanguage string `json:"preferredLanguage"`
}

// getMicrosoftOAuthConfig creates the OAuth2 config for Microsoft
func (m *MicrosoftOauth) getMicrosoftOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     m.Auth.Config.Providers.Microsoft.ClientID,
		ClientSecret: m.Auth.Config.Providers.Microsoft.ClientSecret,
		RedirectURL:  m.Auth.Config.Providers.Microsoft.RedirectURL,
		Scopes: []string{
			"User.Read",
			"email",
			"profile",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		},
	}
}

// SignIn initiates the Microsoft OAuth flow
func (m *MicrosoftOauth) SignIn(w http.ResponseWriter, r *http.Request) {
	// Create service instance
	service := services.NewAuthService(m.Auth)

	// Generate OAuth state using service
	stateResponse, err := service.GenerateOAuthState(r.Context(), dto.Microsoft)
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
	url, err := service.GetOAuthSignInURL(r.Context(), dto.Microsoft, stateResponse.State)
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

	// Redirect user to Microsoft's consent page
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback handles the OAuth callback from Microsoft
func (m *MicrosoftOauth) Callback(w http.ResponseWriter, r *http.Request) {
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
	service := services.NewAuthService(m.Auth)

	// Prepare callback request
	req := &dto.OAuthCallbackRequest{
		Provider: dto.Microsoft,
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
			Name:     m.Auth.Config.AuthConfig.Cookie.Name,
			Value:    response.Tokens.AccessToken,
			Path:     m.Auth.Config.AuthConfig.Cookie.Path,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(m.Auth.Config.AuthConfig.JWT.AccessTokenTTL.Seconds()),
		}
		http.SetCookie(w, accessTokenCookie)

		// Set refresh token cookie
		refreshTokenCookie := &http.Cookie{
			Name:     "refresh_token",
			Value:    response.Tokens.RefreshToken,
			Path:     m.Auth.Config.AuthConfig.Cookie.Path,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(m.Auth.Config.AuthConfig.JWT.RefreshTokenTTL.Seconds()),
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
	http.Redirect(w, r, m.Auth.Config.App.FrontendURL, http.StatusTemporaryRedirect)
}

// getUserInfo gets user information from Microsoft
func (m *MicrosoftOauth) getUserInfo(accessToken string) (*MicrosoftUserInfo, error) {
	url := "https://graph.microsoft.com/v1.0/me"
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

	var userInfo MicrosoftUserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return nil, err
	}

	return &userInfo, nil
}
