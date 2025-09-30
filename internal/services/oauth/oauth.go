package oauth_service

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

// OAuthService implements OAuth business logic
func (s *OAuthService) GenerateOAuthState(ctx context.Context, provider dto.OAuthProvider) (*dto.OAuthStateResponse, *types.GoAuthError) {
	state, err := s.tokenMgr.GenerateRandomToken(20)
	if err != nil {
		s.logger.Errorf("failed to generate state: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	return &dto.OAuthStateResponse{
		State: state,
	}, nil
}

func (s *OAuthService) GetOAuthSignInURL(ctx context.Context, provider dto.OAuthProvider, state string) (string, *types.GoAuthError) {
	config, err := s.getOAuthConfig(provider)
	if err != nil {
		s.logger.Errorf("failed to get OAuth config: %v", err)
		return "", types.NewInternalError(err.Error())
	}

	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return url, nil
}

func (s *OAuthService) HandleOAuthCallback(ctx context.Context, req *dto.OAuthCallbackRequest) (*dto.OAuthCallbackResponse, *types.GoAuthError) {
	// Get OAuth config
	config, err := s.getOAuthConfig(req.Provider)
	if err != nil {
		return nil, types.NewInternalError(err.Error())
	}

	// Exchange code for token
	token, err := config.Exchange(ctx, req.Code)
	if err != nil {
		return nil, types.NewInternalError(err.Error())
	}

	// Get user info from provider
	userInfo, err := s.getOAuthUserInfo(ctx, req.Provider, token.AccessToken)
	if err != nil {
		return nil, types.NewInternalError(err.Error())
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
	err = s.userRepo.UpsertUserByEmail(ctx, user)
	if err != nil {
		return nil, types.NewInternalError(err.Error())
	}

	// Generate tokens
	accessToken, refreshToken, err := s.tokenMgr.GenerateTokens(user)
	if err != nil {
		return nil, types.NewInternalError(err.Error())
	}

	// // Save refresh token
	// hashedRefreshToken, err := s.Auth.TokenManager.HashToken(refreshToken)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to hash refresh token: %w", err)
	// }

	// err = s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedRefreshToken, models.RefreshToken, s.Auth.Config.AuthConfig.JWT.RefreshTokenTTL)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to save refresh token: %w", err)
	// }

	// Prepare response
	userData := &dto.UserResponseData{
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
		ExpiresAt:    time.Now().Add(s.config.AuthConfig.JWT.AccessTokenTTL),
	}

	return &dto.OAuthCallbackResponse{
		Message: "OAuth authentication successful",
		User:    userData,
		Tokens:  tokenData,
	}, nil
}

func (s *OAuthService) GetOAuthProviders(ctx context.Context) (*dto.OAuthProvidersResponse, *types.GoAuthError) {
	providers := []dto.OAuthProviderConfig{}

	// Check which providers are enabled and configured
	if s.config.Providers.Google.ClientID != "" {
		providers = append(providers, dto.OAuthProviderConfig{
			Provider:    dto.Google,
			ClientID:    s.config.Providers.Google.ClientID,
			RedirectURL: s.config.Providers.Google.RedirectURL,
			Scopes:      []string{"email", "profile"},
			Enabled:     true,
		})
	}

	if s.config.Providers.GitHub.ClientID != "" {
		providers = append(providers, dto.OAuthProviderConfig{
			Provider:    dto.GitHub,
			ClientID:    s.config.Providers.GitHub.ClientID,
			RedirectURL: s.config.Providers.GitHub.RedirectURL,
			Scopes:      []string{"user:email", "read:user"},
			Enabled:     true,
		})
	}

	// Add other providers as needed...

	return &dto.OAuthProvidersResponse{
		Providers: providers,
	}, nil
}

func (s *OAuthService) LinkOAuthAccount(ctx context.Context, userID string, req *dto.OAuthLinkRequest) (*dto.OAuthLinkResponse, *types.GoAuthError) {
	// Get OAuth config
	config, err := s.getOAuthConfig(req.Provider)
	if err != nil {
		s.logger.Errorf("failed to get OAuth config: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Exchange code for token
	token, err := config.Exchange(ctx, req.Code)
	if err != nil {
		s.logger.Errorf("failed to exchange token: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Get user info from provider
	userInfo, err := s.getOAuthUserInfo(ctx, req.Provider, token.AccessToken)
	if err != nil {
		s.logger.Errorf("failed to get user info: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Get existing user
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Errorf("failed to get user: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Update user with OAuth provider info
	user.ProviderId = &userInfo.ProviderID
	user.SignedUpVia = string(userInfo.Provider)
	if userInfo.Avatar != nil {
		user.Avatar = userInfo.Avatar
	}

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return nil, types.NewInternalError(err.Error())
	}

	return &dto.OAuthLinkResponse{
		Message: "OAuth account linked successfully",
		Linked:  true,
	}, nil
}

func (s *OAuthService) UnlinkOAuthAccount(ctx context.Context, userID string, req *dto.OAuthUnlinkRequest) (*dto.OAuthLinkResponse, *types.GoAuthError) {
	// Get existing user
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Errorf("failed to get user: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Unlink OAuth account
	user.ProviderId = nil
	user.SignedUpVia = "email" // Default to email

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		s.logger.Errorf("failed to update user: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	return &dto.OAuthLinkResponse{
		Message: "OAuth account unlinked successfully",
		Linked:  false,
	}, nil
}

func (s *OAuthService) GetUserOAuthAccounts(ctx context.Context, userID string) (*dto.OAuthUserAccountsResponse, *types.GoAuthError) {
	// Get existing user
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Errorf("failed to get user: %v", err)
		return nil, types.NewInternalError(err.Error())
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

func (s *OAuthService) getOAuthConfig(provider dto.OAuthProvider) (*oauth2.Config, error) {
	switch provider {
	case dto.Google:
		return &oauth2.Config{
			ClientID:     s.config.Providers.Google.ClientID,
			ClientSecret: s.config.Providers.Google.ClientSecret,
			RedirectURL:  s.config.Providers.Google.RedirectURL,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		}, nil
	case dto.GitHub:
		return &oauth2.Config{
			ClientID:     s.config.Providers.GitHub.ClientID,
			ClientSecret: s.config.Providers.GitHub.ClientSecret,
			RedirectURL:  s.config.Providers.GitHub.RedirectURL,
			Scopes: []string{
				"user:email",
				"read:user",
			},
			Endpoint: github.Endpoint,
		}, nil
	case dto.Apple:
		return &oauth2.Config{
			ClientID:     s.config.Providers.Apple.ClientID,
			ClientSecret: s.config.Providers.Apple.ClientSecret,
			RedirectURL:  s.config.Providers.Apple.RedirectURL,
			Scopes:       []string{"email", "name"},
		}, nil
	case dto.Facebook:
		return &oauth2.Config{
			ClientID:     s.config.Providers.Facebook.ClientID,
			ClientSecret: s.config.Providers.Facebook.ClientSecret,
			RedirectURL:  s.config.Providers.Facebook.RedirectURL,
			Scopes:       []string{"email", "name"},
		}, nil
	case dto.Twitter:
		return &oauth2.Config{
			ClientID:     s.config.Providers.Twitter.ClientID,
			ClientSecret: s.config.Providers.Twitter.ClientSecret,
			RedirectURL:  s.config.Providers.Twitter.RedirectURL,
			Scopes:       []string{"email", "name"},
		}, nil
	case dto.LinkedIn:
		return &oauth2.Config{
			ClientID:     s.config.Providers.LinkedIn.ClientID,
			ClientSecret: s.config.Providers.LinkedIn.ClientSecret,
			RedirectURL:  s.config.Providers.LinkedIn.RedirectURL,
			Scopes:       []string{"email", "name"},
		}, nil
	case dto.Microsoft:
		return &oauth2.Config{
			ClientID:     s.config.Providers.Microsoft.ClientID,
			ClientSecret: s.config.Providers.Microsoft.ClientSecret,
			RedirectURL:  s.config.Providers.Microsoft.RedirectURL,
			Scopes:       []string{"email", "name"},
		}, nil
	case dto.Discord:
		return &oauth2.Config{
			ClientID:     s.config.Providers.Discord.ClientID,
			ClientSecret: s.config.Providers.Discord.ClientSecret,
			RedirectURL:  s.config.Providers.Discord.RedirectURL,
			Scopes:       []string{"email", "name"},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported OAuth provider: %s", provider)
	}
}

func (s *OAuthService) getOAuthUserInfo(ctx context.Context, provider dto.OAuthProvider, accessToken string) (*dto.OAuthUserInfo, *types.GoAuthError) {
	switch provider {
	case dto.Google:
		return s.getGoogleUserInfo(ctx, accessToken)
	case dto.GitHub:
		return s.getGitHubUserInfo(ctx, accessToken)
	default:
		return nil, types.NewInternalError(fmt.Sprintf("unsupported OAuth provider: %s", provider))
	}
}
