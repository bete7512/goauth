package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

// OAuthService implements OAuth business logic
func (s *AuthService) GenerateOAuthState(ctx context.Context, provider dto.OAuthProvider) (*dto.OAuthStateResponse, error) {
	state, err := s.Auth.TokenManager.GenerateRandomToken(20)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	return &dto.OAuthStateResponse{
		State: state,
	}, nil
}

func (s *AuthService) GetOAuthSignInURL(ctx context.Context, provider dto.OAuthProvider, state string) (string, error) {
	config, err := s.getOAuthConfig(provider)
	if err != nil {
		return "", err
	}

	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return url, nil
}

func (s *AuthService) HandleOAuthCallback(ctx context.Context, req *dto.OAuthCallbackRequest) (*dto.OAuthCallbackResponse, error) {
	// Get OAuth config
	config, err := s.getOAuthConfig(req.Provider)
	if err != nil {
		return nil, err
	}

	// Exchange code for token
	token, err := config.Exchange(ctx, req.Code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	// Get user info from provider
	userInfo, err := s.getOAuthUserInfo(ctx, req.Provider, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Create or update user
	user := &models.User{
		Email:         userInfo.Email,
		FirstName:     userInfo.FirstName,
		LastName:      userInfo.LastName,
		SignedUpVia:   string(userInfo.Provider),
		ProviderId:    &userInfo.ProviderID,
		Avatar:        userInfo.Avatar,
		EmailVerified: &userInfo.VerifiedEmail,
	}

	// Upsert user
	err = s.Auth.Repository.GetUserRepository().UpsertUserByEmail(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to create/update user: %w", err)
	}

	// Generate tokens
	accessToken, refreshToken, err := s.Auth.TokenManager.GenerateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Save refresh token
	hashedRefreshToken, err := s.Auth.TokenManager.HashToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash refresh token: %w", err)
	}

	err = s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedRefreshToken, models.RefreshToken, s.Auth.Config.AuthConfig.JWT.RefreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	// Prepare response
	userData := &dto.UserData{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	tokenData := &dto.TokenData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(s.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
	}

	return &dto.OAuthCallbackResponse{
		Message: "OAuth authentication successful",
		User:    userData,
		Tokens:  tokenData,
	}, nil
}

func (s *AuthService) GetOAuthProviders(ctx context.Context) (*dto.OAuthProvidersResponse, error) {
	providers := []dto.OAuthProviderConfig{}

	// Check which providers are enabled and configured
	if s.Auth.Config.Providers.Google.ClientID != "" {
		providers = append(providers, dto.OAuthProviderConfig{
			Provider:    dto.Google,
			ClientID:    s.Auth.Config.Providers.Google.ClientID,
			RedirectURL: s.Auth.Config.Providers.Google.RedirectURL,
			Scopes:      []string{"email", "profile"},
			Enabled:     true,
		})
	}

	if s.Auth.Config.Providers.GitHub.ClientID != "" {
		providers = append(providers, dto.OAuthProviderConfig{
			Provider:    dto.GitHub,
			ClientID:    s.Auth.Config.Providers.GitHub.ClientID,
			RedirectURL: s.Auth.Config.Providers.GitHub.RedirectURL,
			Scopes:      []string{"user:email", "read:user"},
			Enabled:     true,
		})
	}

	// Add other providers as needed...

	return &dto.OAuthProvidersResponse{
		Providers: providers,
	}, nil
}

func (s *AuthService) LinkOAuthAccount(ctx context.Context, userID string, req *dto.OAuthLinkRequest) (*dto.OAuthLinkResponse, error) {
	// Get OAuth config
	config, err := s.getOAuthConfig(req.Provider)
	if err != nil {
		return nil, err
	}

	// Exchange code for token
	token, err := config.Exchange(ctx, req.Code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	// Get user info from provider
	userInfo, err := s.getOAuthUserInfo(ctx, req.Provider, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Get existing user
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Update user with OAuth provider info
	user.ProviderId = &userInfo.ProviderID
	user.SignedUpVia = string(userInfo.Provider)
	if userInfo.Avatar != nil {
		user.Avatar = userInfo.Avatar
	}

	err = s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &dto.OAuthLinkResponse{
		Message: "OAuth account linked successfully",
		Linked:  true,
	}, nil
}

func (s *AuthService) UnlinkOAuthAccount(ctx context.Context, userID string, req *dto.OAuthUnlinkRequest) (*dto.OAuthLinkResponse, error) {
	// Get existing user
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Unlink OAuth account
	user.ProviderId = nil
	user.SignedUpVia = "email" // Default to email

	err = s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &dto.OAuthLinkResponse{
		Message: "OAuth account unlinked successfully",
		Linked:  false,
	}, nil
}

func (s *AuthService) GetUserOAuthAccounts(ctx context.Context, userID string) (*dto.OAuthUserAccountsResponse, error) {
	// Get existing user
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	accounts := []dto.OAuthUser{}

	// If user has a provider ID, they have a linked OAuth account
	if user.ProviderId != nil {
		provider := dto.OAuthProvider(user.SignedUpVia)
		accounts = append(accounts, dto.OAuthUser{
			ID:            user.ID,
			ProviderID:    *user.ProviderId,
			Email:         user.Email,
			FirstName:     user.FirstName,
			LastName:      user.LastName,
			Avatar:        user.Avatar,
			Provider:      provider,
			VerifiedEmail: user.EmailVerified != nil && *user.EmailVerified,
			CreatedAt:     user.CreatedAt,
			UpdatedAt:     user.UpdatedAt,
		})
	}

	return &dto.OAuthUserAccountsResponse{
		Accounts: accounts,
	}, nil
}

// Helper methods

func (s *AuthService) getOAuthConfig(provider dto.OAuthProvider) (*oauth2.Config, error) {
	switch provider {
	case dto.Google:
		return &oauth2.Config{
			ClientID:     s.Auth.Config.Providers.Google.ClientID,
			ClientSecret: s.Auth.Config.Providers.Google.ClientSecret,
			RedirectURL:  s.Auth.Config.Providers.Google.RedirectURL,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		}, nil
	case dto.GitHub:
		return &oauth2.Config{
			ClientID:     s.Auth.Config.Providers.GitHub.ClientID,
			ClientSecret: s.Auth.Config.Providers.GitHub.ClientSecret,
			RedirectURL:  s.Auth.Config.Providers.GitHub.RedirectURL,
			Scopes: []string{
				"user:email",
				"read:user",
			},
			Endpoint: github.Endpoint,
		}, nil
	case dto.Apple:
		return &oauth2.Config{
			ClientID:     s.Auth.Config.Providers.Apple.ClientID,
			ClientSecret: s.Auth.Config.Providers.Apple.ClientSecret,
			RedirectURL:  s.Auth.Config.Providers.Apple.RedirectURL,
			Scopes:       []string{"email", "name"},
		}, nil
	case dto.Facebook:
		return &oauth2.Config{
			ClientID:     s.Auth.Config.Providers.Facebook.ClientID,
			ClientSecret: s.Auth.Config.Providers.Facebook.ClientSecret,
			RedirectURL:  s.Auth.Config.Providers.Facebook.RedirectURL,
			Scopes:       []string{"email", "name"},
		}, nil
	case dto.Twitter:
		return &oauth2.Config{
			ClientID:     s.Auth.Config.Providers.Twitter.ClientID,
			ClientSecret: s.Auth.Config.Providers.Twitter.ClientSecret,
			RedirectURL:  s.Auth.Config.Providers.Twitter.RedirectURL,
			Scopes:       []string{"email", "name"},
		}, nil
	case dto.LinkedIn:
		return &oauth2.Config{
			ClientID:     s.Auth.Config.Providers.LinkedIn.ClientID,
			ClientSecret: s.Auth.Config.Providers.LinkedIn.ClientSecret,
			RedirectURL:  s.Auth.Config.Providers.LinkedIn.RedirectURL,
			Scopes:       []string{"email", "name"},
		}, nil
	case dto.Microsoft:
		return &oauth2.Config{
			ClientID:     s.Auth.Config.Providers.Microsoft.ClientID,
			ClientSecret: s.Auth.Config.Providers.Microsoft.ClientSecret,
			RedirectURL:  s.Auth.Config.Providers.Microsoft.RedirectURL,
			Scopes:       []string{"email", "name"},
		}, nil
	case dto.Discord:
		return &oauth2.Config{
			ClientID:     s.Auth.Config.Providers.Discord.ClientID,
			ClientSecret: s.Auth.Config.Providers.Discord.ClientSecret,
			RedirectURL:  s.Auth.Config.Providers.Discord.RedirectURL,
			Scopes:       []string{"email", "name"},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported OAuth provider: %s", provider)
	}
}

func (s *AuthService) getOAuthUserInfo(ctx context.Context, provider dto.OAuthProvider, accessToken string) (*dto.OAuthUserInfo, error) {
	switch provider {
	case dto.Google:
		return s.getGoogleUserInfo(ctx, accessToken)
	case dto.GitHub:
		return s.getGitHubUserInfo(ctx, accessToken)
	default:
		return nil, fmt.Errorf("unsupported OAuth provider: %s", provider)
	}
}

func (s *AuthService) getGoogleUserInfo(ctx context.Context, accessToken string) (*dto.OAuthUserInfo, error) {
	url := "https://www.googleapis.com/oauth2/v2/userinfo"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

	var googleUser struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
	}

	err = json.Unmarshal(body, &googleUser)
	if err != nil {
		return nil, err
	}

	firstName := googleUser.GivenName
	if firstName == "" {
		firstName = googleUser.Name
	}

	return &dto.OAuthUserInfo{
		ProviderID:    googleUser.ID,
		Email:         googleUser.Email,
		FirstName:     firstName,
		LastName:      googleUser.FamilyName,
		Avatar:        &googleUser.Picture,
		Provider:      dto.Google,
		VerifiedEmail: googleUser.VerifiedEmail,
	}, nil
}

func (s *AuthService) getGitHubUserInfo(ctx context.Context, accessToken string) (*dto.OAuthUserInfo, error) {
	url := "https://api.github.com/user"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

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

	var githubUser struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}

	err = json.Unmarshal(body, &githubUser)
	if err != nil {
		return nil, err
	}

	// If email is private, fetch it separately
	if githubUser.Email == "" {
		email, err := s.getGitHubPrimaryEmail(ctx, accessToken)
		if err != nil {
			return nil, err
		}
		githubUser.Email = email
	}

	providerID := fmt.Sprintf("%d", githubUser.ID)
	firstName := githubUser.Name
	if firstName == "" {
		firstName = githubUser.Login
	}

	return &dto.OAuthUserInfo{
		ProviderID:    providerID,
		Email:         githubUser.Email,
		FirstName:     firstName,
		LastName:      "", // GitHub doesn't provide separated name fields
		Avatar:        &githubUser.AvatarURL,
		Provider:      dto.GitHub,
		VerifiedEmail: true, // GitHub emails are typically verified
	}, nil
}

func (s *AuthService) getGitHubPrimaryEmail(ctx context.Context, accessToken string) (string, error) {
	url := "https://api.github.com/user/emails"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get emails: %s", string(body))
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	err = json.Unmarshal(body, &emails)
	if err != nil {
		return "", err
	}

	// Find primary email
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	// If no primary verified email, return the first verified email
	for _, email := range emails {
		if email.Verified {
			return email.Email, nil
		}
	}

	return "", fmt.Errorf("no verified email found")
}
