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

type LinkedInOauth struct {
	Auth *config.Auth
}

func NewLinkedInOauth(auth *config.Auth) *LinkedInOauth {
	return &LinkedInOauth{
		Auth: auth,
	}
}

// LinkedInUserInfo represents the user information returned by LinkedIn
type LinkedInUserInfo struct {
	ID        string `json:"id"`
	FirstName struct {
		Localized struct {
			EnUS string `json:"en_US"`
		} `json:"localized"`
	} `json:"firstName"`
	LastName struct {
		Localized struct {
			EnUS string `json:"en_US"`
		} `json:"localized"`
	} `json:"lastName"`
	ProfilePicture struct {
		DisplayImage struct {
			Elements []struct {
				Identifiers []struct {
					Identifier string `json:"identifier"`
				} `json:"identifiers"`
			} `json:"elements"`
		} `json:"displayImage"`
	} `json:"profilePicture"`
	EmailAddress string `json:"emailAddress"`
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
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://www.linkedin.com/oauth/v2/authorization",
			TokenURL: "https://www.linkedin.com/oauth/v2/accessToken",
		},
	}
}

// SignIn initiates the LinkedIn OAuth flow
func (l *LinkedInOauth) SignIn(w http.ResponseWriter, r *http.Request) {
	// Create service instance
	service := services.NewAuthService(l.Auth)

	// Generate OAuth state using service
	stateResponse, err := service.GenerateOAuthState(r.Context(), dto.LinkedIn)
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
	url, err := service.GetOAuthSignInURL(r.Context(), dto.LinkedIn, stateResponse.State)
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

	// Redirect user to LinkedIn's consent page
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

	// Create service instance
	service := services.NewAuthService(l.Auth)

	// Prepare callback request
	req := &dto.OAuthCallbackRequest{
		Provider: dto.LinkedIn,
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
			Name:     l.Auth.Config.AuthConfig.Cookie.Name,
			Value:    response.Tokens.AccessToken,
			Path:     l.Auth.Config.AuthConfig.Cookie.Path,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(l.Auth.Config.AuthConfig.JWT.AccessTokenTTL.Seconds()),
		}
		http.SetCookie(w, accessTokenCookie)

		// Set refresh token cookie
		refreshTokenCookie := &http.Cookie{
			Name:     "refresh_token",
			Value:    response.Tokens.RefreshToken,
			Path:     l.Auth.Config.AuthConfig.Cookie.Path,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(l.Auth.Config.AuthConfig.JWT.RefreshTokenTTL.Seconds()),
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
	http.Redirect(w, r, l.Auth.Config.App.FrontendURL, http.StatusTemporaryRedirect)
}

// getUserInfo gets user information from LinkedIn
func (l *LinkedInOauth) getUserInfo(accessToken string) (*LinkedInUserInfo, error) {
	url := "https://api.linkedin.com/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams),emailAddress)"
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

	var userInfo LinkedInUserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return nil, err
	}

	return &userInfo, nil
}
