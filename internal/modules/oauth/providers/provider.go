package providers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"time"
)

// OAuthProvider defines the contract for OAuth providers.
// Each provider (Google, GitHub, Microsoft, Discord) implements this interface.
type OAuthProvider interface {
	// Name returns the provider identifier (e.g., "google", "github")
	Name() string

	// AuthCodeURL builds the authorization URL with state and PKCE parameters
	AuthCodeURL(state string, opts AuthCodeURLOptions) string

	// Exchange exchanges the authorization code for tokens
	Exchange(ctx context.Context, code string, opts ExchangeOptions) (*TokenResponse, error)

	// UserInfo fetches user profile from the provider using the access token
	UserInfo(ctx context.Context, accessToken string) (*UserInfo, error)

	// SupportsOIDC returns true if the provider supports OpenID Connect.
	// OIDC providers (Google, Microsoft) can validate ID tokens instead of calling UserInfo.
	SupportsOIDC() bool

	// ValidateIDToken validates and extracts claims from an ID token (OIDC providers only).
	// Non-OIDC providers should return an error.
	ValidateIDToken(ctx context.Context, idToken string) (*UserInfo, error)
}

// AuthCodeURLOptions contains parameters for building the authorization URL
type AuthCodeURLOptions struct {
	// RedirectURI is the callback URL registered with the provider
	RedirectURI string

	// Scopes to request from the provider
	Scopes []string

	// CodeChallenge is the PKCE S256 code challenge (required if PKCE enabled)
	CodeChallenge string

	// Nonce for OIDC replay protection (optional, used by OIDC providers)
	Nonce string
}

// ExchangeOptions contains parameters for token exchange
type ExchangeOptions struct {
	// RedirectURI must match the one used in AuthCodeURL
	RedirectURI string

	// CodeVerifier is the PKCE code verifier (required if PKCE was used)
	CodeVerifier string
}

// TokenResponse holds tokens from OAuth token exchange
type TokenResponse struct {
	// AccessToken is the OAuth access token
	AccessToken string `json:"access_token"`

	// RefreshToken is the OAuth refresh token (may be empty)
	RefreshToken string `json:"refresh_token,omitempty"`

	// IDToken is the OIDC ID token (OIDC providers only)
	IDToken string `json:"id_token,omitempty"`

	// ExpiresIn is the access token lifetime in seconds
	ExpiresIn int64 `json:"expires_in,omitempty"`

	// TokenType is typically "Bearer"
	TokenType string `json:"token_type,omitempty"`

	// Scope is the granted scopes (may differ from requested)
	Scope string `json:"scope,omitempty"`
}

// UserInfo holds normalized user data from any OAuth provider
type UserInfo struct {
	// ID is the provider's unique identifier for the user (subject)
	ID string `json:"id"`

	// Email is the user's email address
	Email string `json:"email"`

	// EmailVerified indicates if the provider has verified the email
	EmailVerified bool `json:"email_verified"`

	// Name is the user's display name
	Name string `json:"name"`

	// FirstName is the user's given name
	FirstName string `json:"first_name,omitempty"`

	// LastName is the user's family name
	LastName string `json:"last_name,omitempty"`

	// Avatar is the URL to the user's profile picture
	Avatar string `json:"avatar,omitempty"`

	// RawData contains provider-specific data
	RawData map[string]interface{} `json:"raw_data,omitempty"`
}

// BaseProvider provides common functionality shared by all OAuth providers
type BaseProvider struct {
	name         string
	clientID     string
	clientSecret string
	authURL      string
	tokenURL     string
	userInfoURL  string
	scopes       []string
	httpClient   *http.Client
}

// NewBaseProvider creates a new BaseProvider with common configuration
func NewBaseProvider(name, clientID, clientSecret, authURL, tokenURL, userInfoURL string, scopes []string) *BaseProvider {
	return &BaseProvider{
		name:         name,
		clientID:     clientID,
		clientSecret: clientSecret,
		authURL:      authURL,
		tokenURL:     tokenURL,
		userInfoURL:  userInfoURL,
		scopes:       scopes,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Name returns the provider name
func (p *BaseProvider) Name() string {
	return p.name
}

// BuildAuthURL constructs the authorization URL with query parameters
func (p *BaseProvider) BuildAuthURL(state string, opts AuthCodeURLOptions, extraParams map[string]string) string {
	params := url.Values{}
	params.Set("client_id", p.clientID)
	params.Set("redirect_uri", opts.RedirectURI)
	params.Set("response_type", "code")
	params.Set("state", state)

	// Use provided scopes or defaults
	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = p.scopes
	}
	if len(scopes) > 0 {
		scopeStr := ""
		for i, s := range scopes {
			if i > 0 {
				scopeStr += " "
			}
			scopeStr += s
		}
		params.Set("scope", scopeStr)
	}

	// Add PKCE code challenge if provided
	if opts.CodeChallenge != "" {
		params.Set("code_challenge", opts.CodeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	// Add nonce for OIDC providers
	if opts.Nonce != "" {
		params.Set("nonce", opts.Nonce)
	}

	// Add any extra provider-specific parameters
	for k, v := range extraParams {
		params.Set(k, v)
	}

	return p.authURL + "?" + params.Encode()
}

// HTTPClient returns the HTTP client for making requests
func (p *BaseProvider) HTTPClient() *http.Client {
	return p.httpClient
}

// TokenURL returns the token endpoint URL
func (p *BaseProvider) TokenURL() string {
	return p.tokenURL
}

// UserInfoURL returns the userinfo endpoint URL
func (p *BaseProvider) UserInfoURL() string {
	return p.userInfoURL
}

// ClientID returns the OAuth client ID
func (p *BaseProvider) ClientID() string {
	return p.clientID
}

// ClientSecret returns the OAuth client secret
func (p *BaseProvider) ClientSecret() string {
	return p.clientSecret
}

// PKCE Helper Functions

// GenerateCodeVerifier generates a cryptographically random PKCE code verifier.
// The verifier is a URL-safe base64 string of 32 random bytes.
func GenerateCodeVerifier() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateCodeChallenge generates a PKCE S256 code challenge from a code verifier.
// challenge = BASE64URL(SHA256(verifier))
func GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// GenerateState generates a cryptographically random state parameter.
func GenerateState() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateNonce generates a cryptographically random nonce for OIDC.
func GenerateNonce() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
