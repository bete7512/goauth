// Package session exposes the session-based authentication module.
// Import this package instead of internal/modules/session.
package session

import (
	internal "github.com/bete7512/goauth/internal/modules/session"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// New creates a session-based authentication module.
// customStorage is optional; if nil the module uses deps.Storage.Session() from Initialize.
func New(cfg *config.SessionModuleConfig, customStorage types.SessionStorage) config.Module {
	return internal.New(cfg, customStorage)
}
