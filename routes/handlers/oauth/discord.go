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

type DiscordOauth struct {
	Auth *types.Auth
}

func NewDiscordOauth(auth *types.Auth) *DiscordOauth {
	return &DiscordOauth{
		Auth: auth,
	}
}

// DiscordUserInfo represents the user information returned by Discord
type DiscordUserInfo struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	Avatar        string `json:"avatar"`
	Email         string `json:"email"`
	Verified      bool   `json:"verified"`
	GlobalName    string `json:"global_name"`
}

// getDiscordOAuthConfig creates the OAuth2 config for Discord
func (d *DiscordOauth) getDiscordOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     d.Auth.Config.Providers.Discord.ClientID,
		ClientSecret: d.Auth.Config.Providers.Discord.ClientSecret,
		RedirectURL:  d.Auth.Config.Providers.Discord.RedirectURL,
		Scopes: []string{
			"identify",
			"email",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
	}
}

// SignIn initiates the Discord OAuth flow
func (d *DiscordOauth) SignIn(w http.ResponseWriter, r *http.Request) {
	config := d.getDiscordOAuthConfig()

	// Generate a random state for CSRF protection
	state, err := d.Auth.TokenManager.GenerateRandomToken(32)
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

	// Redirect user to Discord's consent page
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback handles the OAuth callback from Discord
func (d *DiscordOauth) Callback(w http.ResponseWriter, r *http.Request) {
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
	config := d.getDiscordOAuthConfig()

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

	// Get user info from Discord
	userInfo, err := d.getUserInfo(token.AccessToken)
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
	// Build avatar URL if available
	var avatarURL string
	if userInfo.Avatar != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", userInfo.ID, userInfo.Avatar)
	}

	// Use global name for first name if available
	firstName := userInfo.GlobalName
	if firstName == "" {
		firstName = userInfo.Username
	}

	user := models.User{
		Email:      userInfo.Email,
		FirstName:  firstName,
		LastName:   "", // Discord doesn't provide last name
		SigninVia:  "discord",
		ProviderId: &userInfo.ID,
		Avatar:     &avatarURL,
	}

	err = d.Auth.Repository.GetUserRepository().UpsertUserByEmail(&user)
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
	accessToken, refreshToken, err := d.Auth.TokenManager.GenerateTokens(&user)
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
	err = d.Auth.Repository.GetTokenRepository().SaveToken(user.ID, refreshToken, models.RefreshToken, d.Auth.Config.AuthConfig.Cookie.RefreshTokenTTL)
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
		Name:     d.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Path:     d.Auth.Config.AuthConfig.Cookie.Path,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(d.Auth.Config.AuthConfig.Cookie.AccessTokenTTL.Seconds()),
	}
	http.SetCookie(w, tokenCookie)

	// Redirect to the frontend
	http.Redirect(w, r, d.Auth.Config.FrontendURL, http.StatusTemporaryRedirect)
}

// getUserInfo fetches the user information from Discord API
func (d *DiscordOauth) getUserInfo(accessToken string) (*DiscordUserInfo, error) {
	req, err := http.NewRequest("GET", "https://discord.com/api/users/@me", nil)
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

	var userInfo DiscordUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}
