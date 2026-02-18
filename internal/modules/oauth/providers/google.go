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
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
)

var googleDefaultScopes = []string{"openid", "email", "profile"}

// GoogleProvider implements OAuth for Google (OpenID Connect)
type GoogleProvider struct {
	*BaseProvider
	redirectURL string
	pkceEnabled bool
}

// Compile-time check that GoogleProvider implements OAuthProvider
var _ OAuthProvider = (*GoogleProvider)(nil)

// NewGoogleProvider creates a new Google OAuth provider
func NewGoogleProvider(cfg *config.OAuthProviderConfig, apiURL, basePath string) (*GoogleProvider, error) {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = googleDefaultScopes
	}

	redirectURL := cfg.RedirectURL
	if redirectURL == "" {
		redirectURL = fmt.Sprintf("%s%s/oauth/%s/callback", apiURL, basePath, ProviderGoogle)
	}

	pkceEnabled := true
	if !cfg.PKCE {
		pkceEnabled = cfg.PKCE
	}

	return &GoogleProvider{
		BaseProvider: NewBaseProvider(
			ProviderGoogle,
			cfg.ClientID,
			cfg.ClientSecret,
			googleAuthURL,
			googleTokenURL,
			googleUserInfoURL,
			scopes,
		),
		redirectURL: redirectURL,
		pkceEnabled: pkceEnabled,
	}, nil
}

// AuthCodeURL builds the Google authorization URL
func (p *GoogleProvider) AuthCodeURL(state string, opts AuthCodeURLOptions) string {
	if opts.RedirectURI == "" {
		opts.RedirectURI = p.redirectURL
	}

	extraParams := map[string]string{
		"access_type": "offline", // Request refresh token
		"prompt":      "consent", // Force consent to get refresh token
	}

	return p.BuildAuthURL(state, opts, extraParams)
}

// Exchange exchanges the authorization code for tokens
func (p *GoogleProvider) Exchange(ctx context.Context, code string, opts ExchangeOptions) (*TokenResponse, error) {
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
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// UserInfo fetches user profile from Google
func (p *GoogleProvider) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
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

// SupportsOIDC returns true - Google supports OpenID Connect
func (p *GoogleProvider) SupportsOIDC() bool {
	return true
}

// ValidateIDToken validates a Google ID token and extracts user info.
// For simplicity, we use the userinfo endpoint instead of full JWT validation.
// In production, you might want to validate the JWT signature using Google's public keys.
func (p *GoogleProvider) ValidateIDToken(ctx context.Context, idToken string) (*UserInfo, error) {
	// Google's tokeninfo endpoint can validate ID tokens
	tokenInfoURL := fmt.Sprintf("https://oauth2.googleapis.com/tokeninfo?id_token=%s", url.QueryEscape(idToken))

	req, err := http.NewRequestWithContext(ctx, "GET", tokenInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create tokeninfo request: %w", err)
	}

	resp, err := p.HTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to validate ID token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read tokeninfo response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ID token validation failed: %s", string(body))
	}

	var rawData map[string]interface{}
	if err := json.Unmarshal(body, &rawData); err != nil {
		return nil, fmt.Errorf("failed to parse tokeninfo response: %w", err)
	}

	// Verify audience matches our client ID
	if aud, ok := rawData["aud"].(string); ok {
		if aud != p.ClientID() {
			return nil, fmt.Errorf("ID token audience mismatch")
		}
	}

	return p.parseUserInfo(rawData), nil
}

// parseUserInfo normalizes Google user data to UserInfo
func (p *GoogleProvider) parseUserInfo(data map[string]interface{}) *UserInfo {
	info := &UserInfo{
		RawData: data,
	}

	// Google uses "sub" as the unique identifier
	if sub, ok := data["sub"].(string); ok {
		info.ID = sub
	}

	if email, ok := data["email"].(string); ok {
		info.Email = email
	}

	// Google returns email_verified as boolean or string
	switch v := data["email_verified"].(type) {
	case bool:
		info.EmailVerified = v
	case string:
		info.EmailVerified = v == "true"
	}

	if name, ok := data["name"].(string); ok {
		info.Name = name
	}

	if givenName, ok := data["given_name"].(string); ok {
		info.FirstName = givenName
	}

	if familyName, ok := data["family_name"].(string); ok {
		info.LastName = familyName
	}

	if picture, ok := data["picture"].(string); ok {
		info.Avatar = picture
	}

	return info
}
