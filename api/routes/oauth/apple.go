package oauthRoutes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bete7512/goauth/config"
	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/utils"
	"golang.org/x/oauth2"
)

// ===== APPLE OAUTH HANDLER =====

type AppleOauth struct {
	Auth *config.Auth
}

func NewAppleOauth(auth *config.Auth) *AppleOauth {
	return &AppleOauth{
		Auth: auth,
	}
}

// AppleUserInfo represents the user information returned by Apple
type AppleUserInfo struct {
	ID    string `json:"sub"`
	Email string `json:"email"`
	Name  struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"name"`
}

// getAppleOAuthConfig creates the OAuth2 config for Apple
func (a *AppleOauth) getAppleOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.Auth.Config.Providers.Apple.ClientID,
		ClientSecret: a.Auth.Config.Providers.Apple.ClientSecret,
		RedirectURL:  a.Auth.Config.Providers.Apple.RedirectURL,
		Scopes: []string{
			"name",
			"email",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://appleid.apple.com/auth/authorize",
			TokenURL: "https://appleid.apple.com/auth/token",
		},
	}
}

// SignIn initiates the Apple OAuth flow
func (a *AppleOauth) SignIn(w http.ResponseWriter, r *http.Request) {
	config := a.getAppleOAuthConfig()

	// Generate a random state for CSRF protection
	state, err := a.Auth.TokenManager.GenerateRandomToken(32)
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

	// Apple OAuth uses a "response_mode" of "form_post"
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline) + "&response_mode=form_post"
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback handles the OAuth callback from Apple
func (a *AppleOauth) Callback(w http.ResponseWriter, r *http.Request) {
	// Apple returns data via POST, so we need to parse the form
	if err := r.ParseForm(); err != nil {
		utils.RespondWithError(
			w,
			http.StatusBadRequest,
			"Failed to parse form data",
			err,
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
	config := a.getAppleOAuthConfig()

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

	// For Apple, we need to get user info from the ID token
	// The user info is in the form of a JWT token
	var userInfo AppleUserInfo

	// Extract user info from the ID token (JWT)
	idToken := token.Extra("id_token").(string)
	if idToken != "" {
		// Extract user info from the ID token
		// Note: In a real implementation, you would need to validate the JWT
		// and decode it properly with a JWT library
		userInfo, err = a.extractUserInfoFromJWT(idToken)
		if err != nil {
			utils.RespondWithError(
				w,
				http.StatusInternalServerError,
				"Failed to decode user info: "+err.Error(),
				err,
			)
			return
		}
	}

	// Apple may also return user data in the initial request (only the first time)
	// Check if user data was provided
	userData := r.FormValue("user")
	if userData != "" {
		// Parse the user data JSON
		var appleUser struct {
			Name struct {
				FirstName string `json:"firstName"`
				LastName  string `json:"lastName"`
			} `json:"name"`
		}

		if err := json.Unmarshal([]byte(userData), &appleUser); err == nil {
			userInfo.Name.FirstName = appleUser.Name.FirstName
			userInfo.Name.LastName = appleUser.Name.LastName
		}
	}

	// Create or update user in your system
	user := models.User{
		Email: userInfo.Email,
		FirstName: func() string {
			if userInfo.Name.FirstName != "" {
				return userInfo.Name.FirstName
			}
			return userInfo.Email // Fallback to email if no name provided
		}(),
		LastName:    userInfo.Name.LastName,
		SignedUpVia: "apple",
		ProviderId:  &userInfo.ID,
		Avatar:      nil, // Apple doesn't provide avatar
	}

	err = a.Auth.Repository.GetUserRepository().UpsertUserByEmail(r.Context(), &user)
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
	accessToken, refreshToken, err := a.Auth.TokenManager.GenerateTokens(&user)
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
	err = a.Auth.Repository.GetTokenRepository().SaveToken(r.Context(), user.ID, refreshToken, models.RefreshToken, a.Auth.Config.AuthConfig.JWT.RefreshTokenTTL)
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
		Name:     a.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Path:     a.Auth.Config.AuthConfig.Cookie.Path,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(a.Auth.Config.AuthConfig.JWT.AccessTokenTTL.Seconds()),
	}
	http.SetCookie(w, tokenCookie)

	// Redirect to the frontend
	http.Redirect(w, r, a.Auth.Config.App.FrontendURL, http.StatusTemporaryRedirect)
}

// extractUserInfoFromJWT extracts user info from Apple's ID token
func (a *AppleOauth) extractUserInfoFromJWT(idToken string) (AppleUserInfo, error) {
	// In a real implementation, you would need to validate the JWT
	// and decode it properly with a JWT library
	// This is a simplified implementation for demonstration purposes

	// Split the token into parts
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return AppleUserInfo{}, fmt.Errorf("invalid token format")
	}

	// Decode the payload (middle part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return AppleUserInfo{}, fmt.Errorf("failed to decode token payload: %v", err)
	}

	// Parse the JSON payload
	var userInfo AppleUserInfo
	if err := json.Unmarshal(payload, &userInfo); err != nil {
		return AppleUserInfo{}, fmt.Errorf("failed to parse token payload: %v", err)
	}

	return userInfo, nil
}
