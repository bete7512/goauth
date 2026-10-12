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
type AuthCodeURLOptions = providers.AuthCodeURLOptions
type ExchangeOptions = providers.ExchangeOptions
type TokenResponse = providers.TokenResponse
type UserInfo = providers.UserInfo

func NewWithProviders(cfg *config.OAuthModuleConfig, connections map[string]Provider) (config.Module, error) {
	module := internal.New(cfg)
	for name, provider := range connections {
		if err := module.RegisterProvider(name, provider); err != nil {
			return nil, err
		}
	}
	return module, nil
}
