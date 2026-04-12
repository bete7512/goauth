// Package magiclink exposes the magic link passwordless authentication module.
// Import this package instead of internal/modules/magiclink.
package magiclink

import (
	internal "github.com/bete7512/goauth/internal/modules/magiclink"
	"github.com/bete7512/goauth/pkg/config"
)

// New creates a magic link authentication module.
// Pass nil for cfg to use safe defaults.
// To provide custom storage, set cfg.CustomStorage.
func New(cfg *config.MagicLinkModuleConfig) config.Module {
	return internal.New(cfg)
}
