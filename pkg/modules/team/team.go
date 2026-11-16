// Package team exposes the team module: nested teams inside organizations.
// Import this package instead of internal/modules/team.
package team

import (
	internal "github.com/bete7512/goauth/internal/modules/team"
	"github.com/bete7512/goauth/pkg/config"
)

// Config is the configuration for the team module.
type Config = internal.Config

// DefaultMaxTeams is the default limit of teams per organization.
const DefaultMaxTeams = internal.DefaultMaxTeams

// New creates the team module. It needs the organization module. Pass nil
// for the defaults.
func New(cfg *Config) config.Module {
	return internal.New(cfg)
}
