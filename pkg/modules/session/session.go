// Package session exposes the session-based authentication module.
// Import this package instead of internal/modules/session.
package session

import (
	internal "github.com/bete7512/goauth/internal/modules/session"
	"github.com/bete7512/goauth/pkg/config"
)

// New creates a session-based authentication module.
// Pass nil for cfg to use safe defaults.
// To provide custom storage, set cfg.CustomStorage.
func New(cfg *config.SessionModuleConfig) config.Module {
	return internal.New(cfg)
}
