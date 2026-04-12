// Package oauth exposes the OAuth authentication module.
// Import this package instead of internal/modules/oauth.
package oauth

import (
	internal "github.com/bete7512/goauth/internal/modules/oauth"
	"github.com/bete7512/goauth/pkg/config"
)

// New creates the OAuth module.
// Pass nil for cfg to use safe defaults.
// To provide custom storage, set cfg.CustomCoreStorage / cfg.CustomOAuthStorage / cfg.CustomSessionStorage.
func New(cfg *config.OAuthModuleConfig) config.Module {
	return internal.New(cfg)
}
