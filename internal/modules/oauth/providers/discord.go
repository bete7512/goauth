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
	discordAuthURL     = "https://discord.com/api/oauth2/authorize"
	discordTokenURL    = "https://discord.com/api/oauth2/token"
	discordUserInfoURL = "https://discord.com/api/users/@me"
)

var discordDefaultScopes = []string{"identify", "email"}

// DiscordProvider implements OAuth for Discord
type DiscordProvider struct {
	*BaseProvider
	redirectURL string
	pkceEnabled bool
}

// Compile-time check that DiscordProvider implements OAuthProvider
var _ OAuthProvider = (*DiscordProvider)(nil)

// NewDiscordProvider creates a new Discord OAuth provider
func NewDiscordProvider(cfg *config.OAuthProviderConfig, apiURL, basePath string) (*DiscordProvider, error) {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = discordDefaultScopes
	}

	redirectURL := cfg.RedirectURL
	if redirectURL == "" {
		redirectURL = fmt.Sprintf("%s%s/oauth/%s/callback", apiURL, basePath, ProviderDiscord)
	}

	pkceEnabled := true
	if !cfg.PKCE {
		pkceEnabled = cfg.PKCE
	}

	return &DiscordProvider{
		BaseProvider: NewBaseProvider(
			ProviderDiscord,
			cfg.ClientID,
			cfg.ClientSecret,
			discordAuthURL,
			discordTokenURL,
			discordUserInfoURL,
			scopes,
		),
		redirectURL: redirectURL,
		pkceEnabled: pkceEnabled,
	}, nil
}

// AuthCodeURL builds the Discord authorization URL
func (p *DiscordProvider) AuthCodeURL(state string, opts AuthCodeURLOptions) string {
	if opts.RedirectURI == "" {
		opts.RedirectURI = p.redirectURL
	}

	// Discord doesn't require extra params
	return p.BuildAuthURL(state, opts, nil)
}

// Exchange exchanges the authorization code for tokens
func (p *DiscordProvider) Exchange(ctx context.Context, code string, opts ExchangeOptions) (*TokenResponse, error) {
	if opts.RedirectURI == "" {
		opts.RedirectURI = p.redirectURL
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", p.ClientID())
	data.Set("client_secret", p.ClientSecret())
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

	resp, err := p.HTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("token exchange failed: %s - %s", errResp.Error, errResp.Description)
		}
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// UserInfo fetches user profile from Discord
func (p *DiscordProvider) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.UserInfoURL(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

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

	return p.parseUserInfo(rawData), nil
}

// SupportsOIDC returns false - Discord uses OAuth2, not OIDC
func (p *DiscordProvider) SupportsOIDC() bool {
	return false
}

// ValidateIDToken is not supported by Discord (not an OIDC provider)
func (p *DiscordProvider) ValidateIDToken(ctx context.Context, idToken string) (*UserInfo, error) {
	return nil, fmt.Errorf("Discord does not support OIDC ID tokens")
}

// parseUserInfo normalizes Discord user data to UserInfo
func (p *DiscordProvider) parseUserInfo(data map[string]interface{}) *UserInfo {
	info := &UserInfo{
		RawData: data,
	}

	// Discord uses string "id"
	if id, ok := data["id"].(string); ok {
		info.ID = id
	}

	if email, ok := data["email"].(string); ok {
		info.Email = email
	}

	// Discord returns "verified" for email verification status
	if verified, ok := data["verified"].(bool); ok {
		info.EmailVerified = verified
	}

	// Discord has username and global_name
	if globalName, ok := data["global_name"].(string); ok && globalName != "" {
		info.Name = globalName
	} else if username, ok := data["username"].(string); ok {
		info.Name = username
	}

	// Discord doesn't separate first/last name
	// We could split Name but that's unreliable

	// Construct avatar URL if avatar hash is present
	if avatarHash, ok := data["avatar"].(string); ok && avatarHash != "" {
		if id, ok := data["id"].(string); ok {
			// Discord CDN URL format
			info.Avatar = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", id, avatarHash)
		}
	}

	return info
}
