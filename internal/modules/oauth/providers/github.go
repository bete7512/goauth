package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/bete7512/goauth/pkg/config"
)

const (
	githubAuthURL     = "https://github.com/login/oauth/authorize"
	githubTokenURL    = "https://github.com/login/oauth/access_token"
	githubUserInfoURL = "https://api.github.com/user"
	githubEmailsURL   = "https://api.github.com/user/emails"
)

// Default scopes: user:email gives access to email, read:user gives profile info
var githubDefaultScopes = []string{"user:email", "read:user"}

// GitHubProvider implements OAuth for GitHub
type GitHubProvider struct {
	*BaseProvider
	redirectURL string
	pkceEnabled bool
}

// Compile-time check that GitHubProvider implements OAuthProvider
var _ OAuthProvider = (*GitHubProvider)(nil)

// NewGitHubProvider creates a new GitHub OAuth provider
func NewGitHubProvider(cfg *config.OAuthProviderConfig, apiURL, basePath string) (*GitHubProvider, error) {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = githubDefaultScopes
	}

	redirectURL := cfg.RedirectURL
	if redirectURL == "" {
		redirectURL = fmt.Sprintf("%s%s/oauth/%s/callback", apiURL, basePath, ProviderGitHub)
	}

	pkceEnabled := true
	if !cfg.PKCE {
		pkceEnabled = cfg.PKCE
	}

	return &GitHubProvider{
		BaseProvider: NewBaseProvider(
			ProviderGitHub,
			cfg.ClientID,
			cfg.ClientSecret,
			githubAuthURL,
			githubTokenURL,
			githubUserInfoURL,
			scopes,
		),
		redirectURL: redirectURL,
		pkceEnabled: pkceEnabled,
	}, nil
}

// AuthCodeURL builds the GitHub authorization URL
func (p *GitHubProvider) AuthCodeURL(state string, opts AuthCodeURLOptions) string {
	if opts.RedirectURI == "" {
		opts.RedirectURI = p.redirectURL
	}

	// GitHub doesn't require extra params like Google
	return p.BuildAuthURL(state, opts, nil)
}

// Exchange exchanges the authorization code for tokens
func (p *GitHubProvider) Exchange(ctx context.Context, code string, opts ExchangeOptions) (*TokenResponse, error) {
	if opts.RedirectURI == "" {
		opts.RedirectURI = p.redirectURL
	}

	data := url.Values{}
	data.Set("client_id", p.ClientID())
	data.Set("client_secret", p.ClientSecret())
	data.Set("code", code)
	data.Set("redirect_uri", opts.RedirectURI)

	// Add PKCE code verifier if provided
	if opts.CodeVerifier != "" {
		data.Set("code_verifier", opts.CodeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.TokenURL(), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json") // GitHub requires this for JSON response

	resp, err := p.HTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	// GitHub returns 200 even for errors, need to check response content
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("token exchange failed: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	return &TokenResponse{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		Scope:       tokenResp.Scope,
	}, nil
}

// UserInfo fetches user profile from GitHub
func (p *GitHubProvider) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	// Fetch basic user info
	req, err := http.NewRequestWithContext(ctx, "GET", p.UserInfoURL(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.HTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch userinfo: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read userinfo response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed: %s", string(body))
	}

	var rawData map[string]interface{}
	if err := json.Unmarshal(body, &rawData); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	info := p.parseUserInfo(rawData)

	// The profile email carries no verification status; /user/emails does.
	// Always consult it: confirm a profile email against the list, or pick the
	// primary verified address when the profile hides the email. Without the
	// user:email scope the request fails and the email stays unverified.
	emails, err := p.fetchEmails(ctx, accessToken)
	if err == nil {
		if info.Email != "" {
			info.EmailVerified = emailVerified(emails, info.Email)
		} else {
			info.Email, info.EmailVerified = pickEmail(emails)
		}
	}

	return info, nil
}

// fetchPrimaryEmail fetches the user's primary verified email from GitHub
type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// fetchEmails lists the addresses on the GitHub account with their
// verification status (requires the user:email scope).
func (p *GitHubProvider) fetchEmails(ctx context.Context, accessToken string) ([]githubEmail, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", githubEmailsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create emails request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.HTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch emails: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read emails response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("emails request failed: %s", string(body))
	}

	var emails []githubEmail
	if err := json.Unmarshal(body, &emails); err != nil {
		return nil, fmt.Errorf("failed to parse emails response: %w", err)
	}
	return emails, nil
}

// emailVerified reports whether GitHub lists email as verified.
func emailVerified(emails []githubEmail, email string) bool {
	for _, e := range emails {
		if strings.EqualFold(e.Email, email) && e.Verified {
			return true
		}
	}
	return false
}

// pickEmail chooses the primary verified address, then any verified address,
// then the unverified primary address (reported as unverified).
func pickEmail(emails []githubEmail) (string, bool) {
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, true
		}
	}
	for _, e := range emails {
		if e.Verified {
			return e.Email, true
		}
	}
	for _, e := range emails {
		if e.Primary {
			return e.Email, false
		}
	}
	return "", false
}

// SupportsOIDC returns false - GitHub uses OAuth2, not OIDC
func (p *GitHubProvider) SupportsOIDC() bool {
	return false
}

// ValidateIDToken is not supported by GitHub (not an OIDC provider)
func (p *GitHubProvider) ValidateIDToken(ctx context.Context, idToken string) (*UserInfo, error) {
	return nil, fmt.Errorf("GitHub does not support OIDC ID tokens")
}

// parseUserInfo normalizes GitHub user data to UserInfo
func (p *GitHubProvider) parseUserInfo(data map[string]interface{}) *UserInfo {
	info := &UserInfo{
		RawData: data,
	}

	// GitHub uses numeric "id" as the unique identifier
	if id, ok := data["id"].(float64); ok {
		info.ID = fmt.Sprintf("%.0f", id)
	}

	if email, ok := data["email"].(string); ok {
		info.Email = email
		// GitHub doesn't directly tell us if email is verified in profile
		// We'll update this when we fetch from /user/emails
	}

	if name, ok := data["name"].(string); ok {
		info.Name = name
	}

	// GitHub doesn't separate first/last name, but we can try to parse
	if info.Name != "" {
		parts := strings.SplitN(info.Name, " ", 2)
		if len(parts) >= 1 {
			info.FirstName = parts[0]
		}
		if len(parts) >= 2 {
			info.LastName = parts[1]
		}
	}

	if avatarURL, ok := data["avatar_url"].(string); ok {
		info.Avatar = avatarURL
	}

	return info
}
