// Package invitation exposes the standalone invitation module.
// Import this package instead of internal/modules/invitation.
package invitation

import (
	internal "github.com/bete7512/goauth/internal/modules/invitation"
	"github.com/bete7512/goauth/pkg/config"
)

// Config is the configuration for the invitation module.
type Config = internal.Config

// New creates a standalone invitation module.
// Pass nil for cfg to use safe defaults (7-day expiry, "platform" purpose, unlimited pending).
func New(cfg *Config) config.Module {
	return internal.New(cfg)
}
