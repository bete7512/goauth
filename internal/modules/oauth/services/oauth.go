package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bete7512/goauth/internal/modules/oauth/providers"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// OAuth account type constant
const accountTypeOAuth = "oauth"

// Default state TTL if not configured
const defaultStateTTL = 10 * time.Minute

// InitiateLogin generates state, PKCE, and returns the authorization URL
func (s *oauthService) InitiateLogin(ctx context.Context, providerName, clientRedirectURI string) (string, *types.GoAuthError) {
	// Get provider
	provider, err := s.registry.Get(providerName)
	if err != nil {
		return "", types.NewOAuthProviderNotFoundError(providerName)
	}

	// Generate cryptographically random state
	state, err := providers.GenerateState()
	if err != nil {
		s.logger.Errorf("oauth: failed to generate state: %v", err)
		return "", types.NewInternalError("failed to generate OAuth state").Wrap(err)
	}

	// Generate PKCE code verifier
	codeVerifier, err := providers.GenerateCodeVerifier()
	if err != nil {
		s.logger.Errorf("oauth: failed to generate PKCE verifier: %v", err)
		return "", types.NewInternalError("failed to generate PKCE verifier").Wrap(err)
	}

	// Generate PKCE code challenge
	codeChallenge := providers.GenerateCodeChallenge(codeVerifier)

	// Generate nonce for OIDC
	nonce, _ := providers.GenerateNonce()

	// Determine state TTL
	stateTTL := s.config.StateTTL
	if stateTTL <= 0 {
		stateTTL = defaultStateTTL
	}

	// Store state + PKCE verifier in Token table
	// We use Code field to store the verifier, and Email field to store client redirect URI
	stateToken := &models.Token{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    "", // No user yet
		Type:      models.TokenTypeOAuthState,
		Token:     state,
		Code:      codeVerifier,      // Store verifier in Code field
		Email:     clientRedirectURI, // Store client redirect URI in Email field
		ExpiresAt: time.Now().Add(stateTTL),
		Used:      false,
		CreatedAt: time.Now(),
	}

	if err := s.tokenRepo.Create(ctx, stateToken); err != nil {
		s.logger.Errorf("oauth: failed to store state: %v", err)
		return "", types.NewInternalError("failed to store OAuth state").Wrap(err)
	}

	// Build authorization URL
	redirectURI := s.buildCallbackURL(providerName)
	authURL := provider.AuthCodeURL(state, providers.AuthCodeURLOptions{
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		Nonce:         nonce,
	})

	s.logger.Trace("oauth: initiated login for provider %s", providerName)
	return authURL, nil
}

// HandleCallback validates state, exchanges code, and creates/links user
func (s *oauthService) HandleCallback(ctx context.Context, providerName, code, state string, metadata *types.RequestMetadata) (*OAuthResult, *types.GoAuthError) {
	// 1. Validate state and retrieve PKCE verifier
	stateToken, err := s.tokenRepo.FindByToken(ctx, state)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewOAuthInvalidStateError()
		}
		return nil, types.NewInternalError("failed to find OAuth state").Wrap(err)
	}

	if stateToken.Type != models.TokenTypeOAuthState {
		return nil, types.NewOAuthInvalidStateError()
	}

	if stateToken.ExpiresAt.Before(time.Now()) {
		return nil, types.NewOAuthStateExpiredError()
	}

	if stateToken.Used {
		return nil, types.NewOAuthStateUsedError()
	}

	// Mark state as used immediately to prevent replay
	if err := s.tokenRepo.MarkAsUsed(ctx, stateToken.ID); err != nil {
		s.logger.Errorf("oauth: failed to mark state as used: %v", err)
	}

	codeVerifier := stateToken.Code
	clientRedirectURI := stateToken.Email

	// 2. Get provider
	provider, err := s.registry.Get(providerName)
	if err != nil {
		return nil, types.NewOAuthProviderNotFoundError(providerName)
	}

	// 3. Exchange code for tokens
	redirectURI := s.buildCallbackURL(providerName)
	tokenResp, err := provider.Exchange(ctx, code, providers.ExchangeOptions{
		RedirectURI:  redirectURI,
		CodeVerifier: codeVerifier,
	})
	if err != nil {
		s.logger.Errorf("oauth: token exchange failed for %s: %v", providerName, err)
		return nil, types.NewOAuthTokenExchangeError(err.Error())
	}

	// 4. Get user info (prefer ID token for OIDC providers)
	var userInfo *providers.UserInfo
	if provider.SupportsOIDC() && tokenResp.IDToken != "" {
		userInfo, err = provider.ValidateIDToken(ctx, tokenResp.IDToken)
		if err != nil {
			s.logger.Warnf("oauth: ID token validation failed, falling back to userinfo: %v", err)
			userInfo, err = provider.UserInfo(ctx, tokenResp.AccessToken)
		}
	} else {
		userInfo, err = provider.UserInfo(ctx, tokenResp.AccessToken)
	}

	if err != nil {
		s.logger.Errorf("oauth: failed to get user info from %s: %v", providerName, err)
		return nil, types.NewOAuthUserInfoError(err.Error())
	}

	// 5. Find or create user
	user, isNewUser, authErr := s.findOrCreateUser(ctx, providerName, userInfo, tokenResp)
	if authErr != nil {
		return nil, authErr
	}

	// 6. Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.Warnf("oauth: failed to update last login time: %v", err)
	}

	// 7. Run auth interceptors (2FA challenges, org enrichment, etc.)
	interceptClaims, challenges, _, interceptErr := s.deps.AuthInterceptors.Run(ctx, &types.InterceptParams{
		Phase:    types.PhaseLogin,
		User:     user,
		Metadata: metadata,
	})
	if interceptErr != nil {
		s.logger.Errorf("oauth: auth interceptor failed: %v", interceptErr)
		return nil, types.NewInternalError("Authentication flow interrupted").Wrap(interceptErr)
	}

	// If challenges were issued, return them without generating tokens
	if len(challenges) > 0 {
		return &OAuthResult{
			User:              user,
			IsNewUser:         isNewUser,
			Provider:          providerName,
			ClientRedirectURI: clientRedirectURI,
			Challenges:        challenges,
		}, nil
	}

	var accessToken, refreshToken, sessionID string
	var expiresIn int64

	// 8. Generate auth tokens (session-based or stateless)
	if s.useSessionAuth() {
		// Session-based: create session record and embed session_id in JWT
		sessionID = uuid.Must(uuid.NewV7()).String()

		tokenClaims := map[string]interface{}{
			"oauth_provider": providerName,
			"session_id":     sessionID,
		}
		for k, v := range interceptClaims {
			tokenClaims[k] = v
		}

		accessToken, refreshToken, err = s.securityManager.GenerateTokens(user, tokenClaims)
		if err != nil {
			s.logger.Errorf("oauth: failed to generate tokens: %v", err)
			return nil, types.NewInternalError("failed to generate authentication tokens").Wrap(err)
		}

		// Create session record — store hashed refresh token
		session := &models.Session{
			ID:                    sessionID,
			UserID:                user.ID,
			RefreshToken:          security.HashRefreshToken(refreshToken),
			RefreshTokenExpiresAt: time.Now().Add(s.deps.Config.Security.Session.RefreshTokenTTL),
			ExpiresAt:             time.Now().Add(s.deps.Config.Security.Session.SessionTTL),
			UserAgent:             metadata.UserAgent,
			IPAddress:             metadata.IPAddress,
			CreatedAt:             time.Now(),
			UpdatedAt:             time.Now(),
		}

		if err := s.sessionRepo.Create(ctx, session); err != nil {
			s.logger.Errorf("oauth: failed to create session: %v", err)
			return nil, types.NewInternalError("failed to create session").Wrap(err)
		}

		expiresIn = int64(s.deps.Config.Security.Session.SessionTTL.Seconds())
	} else {
		// Stateless: just generate JWT tokens
		tokenClaims := map[string]interface{}{
			"oauth_provider": providerName,
		}
		for k, v := range interceptClaims {
			tokenClaims[k] = v
		}

		accessToken, refreshToken, err = s.securityManager.GenerateTokens(user, tokenClaims)
		if err != nil {
			s.logger.Errorf("oauth: failed to generate tokens: %v", err)
			return nil, types.NewInternalError("failed to generate authentication tokens").Wrap(err)
		}

		expiresIn = int64(s.deps.Config.Security.Session.AccessTokenTTL.Seconds())
	}

	// 8. Emit event
	if s.deps.Events != nil {
		eventData := &types.OAuthLoginEventData{
			User:                 user,
			Provider:             providerName,
			ProviderUserID:       userInfo.ID,
			ProviderAccessToken:  tokenResp.AccessToken,
			ProviderRefreshToken: tokenResp.RefreshToken,
			IsNewUser:            isNewUser,
			Metadata:             metadata,
		}
		if emitErr := s.deps.Events.EmitAsync(ctx, types.EventAfterOAuthLogin, eventData); emitErr != nil {
			s.logger.Warnf("oauth: failed to emit after login event: %v", emitErr)
		}
	}

	s.logger.Infof("oauth: user %s authenticated via %s (new: %v, session: %v)", user.ID, providerName, isNewUser, s.useSessionAuth())

	return &OAuthResult{
		User:                 user,
		AccessToken:          accessToken,
		RefreshToken:         refreshToken,
		ExpiresIn:            expiresIn,
		IsNewUser:            isNewUser,
		Provider:             providerName,
		ProviderAccessToken:  tokenResp.AccessToken,
		ProviderRefreshToken: tokenResp.RefreshToken,
		ClientRedirectURI:    clientRedirectURI,
		SessionID:            sessionID,
	}, nil
}

// findOrCreateUser finds an existing user or creates a new one
func (s *oauthService) findOrCreateUser(ctx context.Context, providerName string, info *providers.UserInfo, tokenResp *providers.TokenResponse) (*models.User, bool, *types.GoAuthError) {
	// 1. Check if OAuth account already exists for this provider + provider account ID
	existingAccount, err := s.accountRepo.FindByProviderAndAccountID(ctx, providerName, info.ID)
	if err == nil && existingAccount != nil {
		// User already linked, fetch and return
		user, err := s.userRepo.FindByID(ctx, existingAccount.UserID)
		if err == nil && user != nil {
			// Update account tokens if storing is enabled
			if s.config.StoreProviderTokens {
				s.updateAccountTokens(ctx, existingAccount, tokenResp)
			}
			return user, false, nil
		}
		// Orphaned account - remove it
		s.accountRepo.Delete(ctx, existingAccount.ID)
	}

	// 2. Check if user exists with same email
	if info.Email != "" {
		existingUser, err := s.userRepo.FindByEmail(ctx, info.Email)
		if err == nil && existingUser != nil {
			// Check if account linking is allowed
			if !s.config.AllowAccountLinking {
				return nil, false, types.NewOAuthAccountLinkingDisabledError()
			}

			// Link OAuth to existing account
			if linkErr := s.linkProviderToUser(ctx, existingUser.ID, providerName, info.ID, tokenResp); linkErr != nil {
				s.logger.Warnf("oauth: failed to link provider: %v", linkErr)
			}

			// Update email verification if trusted
			if s.config.TrustEmailVerification && info.EmailVerified && !existingUser.EmailVerified {
				existingUser.EmailVerified = true
				if err := s.userRepo.Update(ctx, existingUser); err != nil {
					s.logger.Warnf("oauth: failed to update email verification: %v", err)
				}
			}

			// Emit link event
			if s.deps.Events != nil {
				s.deps.Events.EmitAsync(ctx, types.EventOAuthLinkAdded, &types.OAuthLinkEventData{
					UserID:         existingUser.ID,
					Provider:       providerName,
					ProviderUserID: info.ID,
				})
			}

			return existingUser, false, nil
		}
	}

	// 3. Create new user (if allowed)
	if !s.config.AllowSignup {
		return nil, false, types.NewOAuthSignupDisabledError()
	}

	// Email is required for new users
	if info.Email == "" {
		return nil, false, types.NewOAuthEmailRequiredError()
	}

	now := time.Now()
	user := &models.User{
		ID:            uuid.Must(uuid.NewV7()).String(),
		Email:         info.Email,
		Name:          info.Name,
		FirstName:     info.FirstName,
		LastName:      info.LastName,
		Avatar:        info.Avatar,
		Username:      s.generateUsername(info.Email),
		PasswordHash:  "", // No password for OAuth-only users
		Active:        true,
		EmailVerified: s.config.TrustEmailVerification && info.EmailVerified,
		CreatedAt:     now,
		UpdatedAt:     &now,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		s.logger.Errorf("oauth: failed to create user: %v", err)
		return nil, false, types.NewInternalError("failed to create user").Wrap(err)
	}

	// Link OAuth provider
	if linkErr := s.linkProviderToUser(ctx, user.ID, providerName, info.ID, tokenResp); linkErr != nil {
		s.logger.Warnf("oauth: failed to link provider to new user: %v", linkErr)
	}

	// Emit signup event
	if s.deps.Events != nil {
		s.deps.Events.EmitAsync(ctx, types.EventAfterSignup, &types.UserEventData{
			User: user,
		})

		s.deps.Events.EmitAsync(ctx, types.EventOAuthLinkAdded, &types.OAuthLinkEventData{
			UserID:         user.ID,
			Provider:       providerName,
			ProviderUserID: info.ID,
		})
	}

	return user, true, nil
}

// linkProviderToUser creates an Account record linking the OAuth provider to the user
func (s *oauthService) linkProviderToUser(ctx context.Context, userID, providerName, providerUserID string, tokenResp *providers.TokenResponse) error {
	now := time.Now()
	account := &models.Account{
		ID:                uuid.Must(uuid.NewV7()).String(),
		UserID:            userID,
		Provider:          providerName,
		ProviderAccountID: providerUserID,
		Type:              accountTypeOAuth,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	// Store provider tokens if configured (encrypted at rest)
	if s.config.StoreProviderTokens && tokenResp != nil {
		if tokenResp.AccessToken != "" {
			encrypted, err := s.securityManager.Encrypt(tokenResp.AccessToken)
			if err != nil {
				s.logger.Warnf("oauth: failed to encrypt access token, skipping storage: %v", err)
			} else {
				account.AccessToken = encrypted
			}
		}
		if tokenResp.RefreshToken != "" {
			encrypted, err := s.securityManager.Encrypt(tokenResp.RefreshToken)
			if err != nil {
				s.logger.Warnf("oauth: failed to encrypt refresh token, skipping storage: %v", err)
			} else {
				account.RefreshToken = encrypted
			}
		}
		if tokenResp.IDToken != "" {
			encrypted, err := s.securityManager.Encrypt(tokenResp.IDToken)
			if err != nil {
				s.logger.Warnf("oauth: failed to encrypt ID token, skipping storage: %v", err)
			} else {
				account.IDToken = encrypted
			}
		}
		account.TokenType = tokenResp.TokenType
		account.Scope = tokenResp.Scope
		if tokenResp.ExpiresIn > 0 {
			expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
			account.ExpiresAt = &expiresAt
		}
	}

	return s.accountRepo.Create(ctx, account)
}

// updateAccountTokens updates an existing account's OAuth tokens (encrypted at rest)
func (s *oauthService) updateAccountTokens(ctx context.Context, account *models.Account, tokenResp *providers.TokenResponse) {
	if tokenResp == nil {
		return
	}

	if tokenResp.AccessToken != "" {
		encrypted, err := s.securityManager.Encrypt(tokenResp.AccessToken)
		if err != nil {
			s.logger.Warnf("oauth: failed to encrypt access token on update: %v", err)
		} else {
			account.AccessToken = encrypted
		}
	}
	if tokenResp.RefreshToken != "" {
		encrypted, err := s.securityManager.Encrypt(tokenResp.RefreshToken)
		if err != nil {
			s.logger.Warnf("oauth: failed to encrypt refresh token on update: %v", err)
		} else {
			account.RefreshToken = encrypted
		}
	}
	if tokenResp.IDToken != "" {
		encrypted, err := s.securityManager.Encrypt(tokenResp.IDToken)
		if err != nil {
			s.logger.Warnf("oauth: failed to encrypt ID token on update: %v", err)
		} else {
			account.IDToken = encrypted
		}
	}
	account.TokenType = tokenResp.TokenType
	account.Scope = tokenResp.Scope
	if tokenResp.ExpiresIn > 0 {
		expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		account.ExpiresAt = &expiresAt
	}
	account.UpdatedAt = time.Now()

	if err := s.accountRepo.Update(ctx, account); err != nil {
		s.logger.Warnf("oauth: failed to update account tokens: %v", err)
	}
}

// UnlinkProvider removes an OAuth provider link from a user account
func (s *oauthService) UnlinkProvider(ctx context.Context, userID, providerName string) *types.GoAuthError {
	// Check if the account link exists
	account, err := s.accountRepo.FindByUserIDAndProvider(ctx, userID, providerName)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewOAuthNotLinkedError(providerName)
		}
		return types.NewInternalError("failed to find OAuth account").Wrap(err)
	}

	// Check if user has password or another OAuth provider
	// (Don't allow unlinking if it would leave the user with no login method)
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewUserNotFoundError()
		}
		return types.NewInternalError("failed to find user").Wrap(err)
	}

	if user.PasswordHash == "" {
		// Count other OAuth accounts for this user
		accountCount, err := s.accountRepo.CountByUserID(ctx, userID)
		if err != nil {
			s.logger.Warnf("oauth: failed to count user accounts: %v", err)
			accountCount = 1 // Assume only this one
		}

		if accountCount <= 1 {
			return types.NewGoAuthError(
				types.ErrOAuthNotLinked,
				"Cannot unlink the only login method. Set a password first.",
				400,
			)
		}
	}

	providerUserID := account.ProviderAccountID

	// Delete the account
	if err := s.accountRepo.Delete(ctx, account.ID); err != nil {
		s.logger.Errorf("oauth: failed to unlink provider: %v", err)
		return types.NewInternalError("failed to unlink provider").Wrap(err)
	}

	// Emit event
	if s.deps.Events != nil {
		s.deps.Events.EmitAsync(ctx, types.EventOAuthLinkRemoved, &types.OAuthLinkEventData{
			UserID:         userID,
			Provider:       providerName,
			ProviderUserID: providerUserID,
		})
	}

	s.logger.Infof("oauth: unlinked provider %s from user %s", providerName, userID)
	return nil
}

// GetLinkedProviders returns the list of OAuth providers linked to a user
func (s *oauthService) GetLinkedProviders(ctx context.Context, userID string) ([]string, *types.GoAuthError) {
	accounts, err := s.accountRepo.FindByUserID(ctx, userID)
	if err != nil {
		s.logger.Errorf("oauth: failed to get linked providers: %v", err)
		return nil, types.NewInternalError("failed to get linked providers").Wrap(err)
	}

	var linked []string
	for _, account := range accounts {
		linked = append(linked, account.Provider)
	}

	return linked, nil
}

// ListEnabledProviders returns the list of enabled provider names
func (s *oauthService) ListEnabledProviders() []string {
	return s.registry.List()
}

// Helper functions
// buildCallbackURL constructs the OAuth callback URL for a provider
func (s *oauthService) buildCallbackURL(providerName string) string {
	return fmt.Sprintf("%s%s/oauth/%s/callback", s.apiURL, s.basePath, providerName)
}

// generateUsername creates a username from email
func (s *oauthService) generateUsername(email string) string {
	// Extract local part of email
	parts := strings.Split(email, "@")
	if len(parts) == 0 {
		return uuid.Must(uuid.NewV7()).String()[:8]
	}

	base := strings.ToLower(parts[0])
	// Remove special characters
	base = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, base)

	// Limit length
	if len(base) > 20 {
		base = base[:20]
	}

	// Add random suffix to ensure uniqueness
	return fmt.Sprintf("%s_%s", base, uuid.Must(uuid.NewV7()).String()[:6])
}
