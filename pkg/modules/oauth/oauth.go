// Package oauth exposes the OAuth authentication module.
// Import this package instead of internal/modules/oauth.
package oauth

import (
	internal "github.com/bete7512/goauth/internal/modules/oauth"
	"github.com/bete7512/goauth/pkg/config"
)

// OAuthStorageOptions is re-exported so callers import only from pkg/.
type OAuthStorageOptions = internal.OAuthStorageOptions

// New creates the OAuth module.
// opts is optional; pass nil to source all storage from deps.Storage during Initialize.
func New(cfg *config.OAuthModuleConfig, opts *OAuthStorageOptions) config.Module {
	return internal.New(cfg, opts)
}
