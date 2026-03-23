// Package organization exposes the organization module.
// Import this package instead of internal/modules/organization.
package organization

import (
	internal "github.com/bete7512/goauth/internal/modules/organization"
	"github.com/bete7512/goauth/pkg/config"
)

// Config is the configuration for the organization module.
type Config = internal.Config

// New creates an organization module.
// Pass nil for safe defaults (no auto-create, unlimited members, 7-day invitations).
func New(cfg *Config) config.Module {
	return internal.New(cfg)
}
