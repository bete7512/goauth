// Package audit exposes the audit-log module.
// Import this package instead of internal/modules/audit.
package audit

import (
	internal "github.com/bete7512/goauth/internal/modules/audit"
	"github.com/bete7512/goauth/pkg/config"
)

// Config is re-exported so callers import only from pkg/.
type Config = internal.Config

// New creates the audit module.
// Pass nil for cfg to use safe defaults: all event types tracked, 90/365/forever retention.
func New(cfg *Config) config.Module {
	return internal.New(cfg)
}
