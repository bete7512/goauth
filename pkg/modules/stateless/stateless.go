// Package stateless exposes the stateless JWT authentication module.
// Import this package instead of internal/modules/stateless.
package stateless

import (
	internal "github.com/bete7512/goauth/internal/modules/stateless"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// New creates a stateless JWT authentication module.
// customStorage is optional; if nil the module uses deps.Storage.Core() from Initialize.
func New(cfg *config.StatelessModuleConfig, customStorage types.CoreStorage) config.Module {
	return internal.New(cfg, customStorage)
}
