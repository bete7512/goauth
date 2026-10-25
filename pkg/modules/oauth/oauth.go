// Package oauth exposes the OAuth authentication module.
// Import this package instead of internal/modules/oauth.
package oauth

import (
	internal "github.com/bete7512/goauth/internal/modules/oauth"
	"github.com/bete7512/goauth/internal/modules/oauth/providers"
	"github.com/bete7512/goauth/pkg/config"
)

// New creates the OAuth module.
// Pass nil for cfg to use safe defaults.
// To provide custom storage, set cfg.CustomCoreStorage / cfg.CustomOAuthStorage / cfg.CustomSessionStorage.
func New(cfg *config.OAuthModuleConfig) config.Module {
	return internal.New(cfg)
}

// Provider is implemented by trusted application code; it must verify its
// protocol completely before returning identity information.
type Provider = providers.OAuthProvider

// AuthCodeURLOptions carries the redirect URI, scopes and PKCE challenge for a
// provider's authorization URL.
type AuthCodeURLOptions = providers.AuthCodeURLOptions

// ExchangeOptions carries the redirect URI and PKCE verifier used to exchange
// an authorization code.
type ExchangeOptions = providers.ExchangeOptions

// TokenResponse is a provider's token response, including the ID token from
// OIDC providers.
type TokenResponse = providers.TokenResponse

// UserInfo is the identity a provider returns: subject, email, whether the
// provider verified that email, and profile fields.
type UserInfo = providers.UserInfo

// NewWithProviders creates the OAuth module with custom providers registered
// under the given connection names. It fails on an invalid or duplicate name.
func NewWithProviders(cfg *config.OAuthModuleConfig, connections map[string]Provider) (config.Module, error) {
	module := internal.New(cfg)
	for name, provider := range connections {
		if err := module.RegisterProvider(name, provider); err != nil {
			return nil, err
		}
	}
	return module, nil
}
