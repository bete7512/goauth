// Package admin exposes the admin user-management module.
// Import this package instead of internal/modules/admin.
package admin

import (
	internal "github.com/bete7512/goauth/internal/modules/admin"
	"github.com/bete7512/goauth/pkg/config"
)

// Config is re-exported so callers import only from pkg/.
type Config = internal.Config

// New creates the admin module.
// Pass nil for cfg to use an empty default (no custom repositories).
func New(cfg *Config) config.Module {
	return internal.New(cfg)
}
