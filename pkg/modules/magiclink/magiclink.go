// Package magiclink exposes the magic link passwordless authentication module.
// Import this package instead of internal/modules/magiclink.
package magiclink

import (
	internal "github.com/bete7512/goauth/internal/modules/magiclink"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// New creates a magic link authentication module.
// customStorage is optional; if nil the module uses deps.Storage.Core() from Initialize.
func New(cfg *config.MagicLinkModuleConfig, customStorage types.CoreStorage) config.Module {
	return internal.New(cfg, customStorage)
}
