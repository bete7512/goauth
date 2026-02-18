package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/bete7512/goauth/pkg/config"
)

const (
	// Using "common" endpoint for both personal Microsoft accounts and Azure AD
	microsoftAuthURL     = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	microsoftTokenURL    = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	microsoftUserInfoURL = "https://graph.microsoft.com/v1.0/me"
)

var microsoftDefaultScopes = []string{"openid", "email", "profile", "User.Read"}

// MicrosoftProvider implements OAuth for Microsoft (OpenID Connect)
type MicrosoftProvider struct {
	*BaseProvider
	redirectURL string
	pkceEnabled bool
}

// Compile-time check that MicrosoftProvider implements OAuthProvider
var _ OAuthProvider = (*MicrosoftProvider)(nil)

// NewMicrosoftProvider creates a new Microsoft OAuth provider
func NewMicrosoftProvider(cfg *config.OAuthProviderConfig, apiURL, basePath string) (*MicrosoftProvider, error) {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = microsoftDefaultScopes
	}

	redirectURL := cfg.RedirectURL
	if redirectURL == "" {
		redirectURL = fmt.Sprintf("%s%s/oauth/%s/callback", apiURL, basePath, ProviderMicrosoft)
	}

	pkceEnabled := true
	if !cfg.PKCE {
		pkceEnabled = cfg.PKCE
	}

	return &MicrosoftProvider{
		BaseProvider: NewBaseProvider(
			ProviderMicrosoft,
			cfg.ClientID,
			cfg.ClientSecret,
			microsoftAuthURL,
			microsoftTokenURL,
			microsoftUserInfoURL,
			scopes,
		),
		redirectURL: redirectURL,
		pkceEnabled: pkceEnabled,
	}, nil
}

// AuthCodeURL builds the Microsoft authorization URL
func (p *MicrosoftProvider) AuthCodeURL(state string, opts AuthCodeURLOptions) string {
	if opts.RedirectURI == "" {
		opts.RedirectURI = p.redirectURL
	}

	extraParams := map[string]string{
		"response_mode": "query",
	}

	return p.BuildAuthURL(state, opts, extraParams)
}

// Exchange exchanges the authorization code for tokens
func (p *MicrosoftProvider) Exchange(ctx context.Context, code string, opts ExchangeOptions) (*TokenResponse, error) {
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

// UserInfo fetches user profile from Microsoft Graph API
func (p *MicrosoftProvider) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
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

// SupportsOIDC returns true - Microsoft supports OpenID Connect
func (p *MicrosoftProvider) SupportsOIDC() bool {
	return true
}

// ValidateIDToken validates a Microsoft ID token.
// For simplicity, we extract claims without full JWT validation.
// In production, you should validate the signature using Microsoft's public keys.
func (p *MicrosoftProvider) ValidateIDToken(ctx context.Context, idToken string) (*UserInfo, error) {
	// Microsoft ID tokens are JWTs - we'll decode the payload
	// In production, you should validate the signature using Microsoft's JWKS
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid ID token format")
	}

	// Decode the payload (second part)
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ID token payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	// Verify audience matches our client ID
	if aud, ok := claims["aud"].(string); ok {
		if aud != p.ClientID() {
			return nil, fmt.Errorf("ID token audience mismatch")
		}
	}

	return p.parseIDTokenClaims(claims), nil
}

// parseUserInfo normalizes Microsoft Graph user data to UserInfo
func (p *MicrosoftProvider) parseUserInfo(data map[string]interface{}) *UserInfo {
	info := &UserInfo{
		RawData: data,
	}

	// Microsoft uses "id" as the unique identifier
	if id, ok := data["id"].(string); ok {
		info.ID = id
	}

	// Microsoft Graph uses "mail" or "userPrincipalName" for email
	if mail, ok := data["mail"].(string); ok && mail != "" {
		info.Email = mail
	} else if upn, ok := data["userPrincipalName"].(string); ok {
		// userPrincipalName is usually an email for personal accounts
		if strings.Contains(upn, "@") {
			info.Email = upn
		}
	}

	// Microsoft considers emails from Graph API as verified
	if info.Email != "" {
		info.EmailVerified = true
	}

	if displayName, ok := data["displayName"].(string); ok {
		info.Name = displayName
	}

	if givenName, ok := data["givenName"].(string); ok {
		info.FirstName = givenName
	}

	if surname, ok := data["surname"].(string); ok {
		info.LastName = surname
	}

	// Microsoft Graph doesn't return avatar URL directly
	// You'd need to fetch /me/photo, which returns binary data

	return info
}

// parseIDTokenClaims extracts user info from Microsoft ID token claims
func (p *MicrosoftProvider) parseIDTokenClaims(claims map[string]interface{}) *UserInfo {
	info := &UserInfo{
		RawData: claims,
	}

	// "sub" is the unique identifier in ID tokens
	if sub, ok := claims["sub"].(string); ok {
		info.ID = sub
	} else if oid, ok := claims["oid"].(string); ok {
		// oid (object ID) is an alternative identifier
		info.ID = oid
	}

	if email, ok := claims["email"].(string); ok {
		info.Email = email
	} else if preferredUsername, ok := claims["preferred_username"].(string); ok {
		// preferred_username is often the email
		if strings.Contains(preferredUsername, "@") {
			info.Email = preferredUsername
		}
	}

	// Check email verification
	if verified, ok := claims["email_verified"].(bool); ok {
		info.EmailVerified = verified
	} else if info.Email != "" {
		// Microsoft typically verifies emails
		info.EmailVerified = true
	}

	if name, ok := claims["name"].(string); ok {
		info.Name = name
	}

	if givenName, ok := claims["given_name"].(string); ok {
		info.FirstName = givenName
	}

	if familyName, ok := claims["family_name"].(string); ok {
		info.LastName = familyName
	}

	return info
}

// base64URLDecode decodes a base64url-encoded string (used in JWTs)
func base64URLDecode(s string) ([]byte, error) {
	// Use RawURLEncoding which handles the URL-safe alphabet without padding
	return base64.RawURLEncoding.DecodeString(s)
}
