// Package stateless exposes the stateless JWT authentication module.
// Import this package instead of internal/modules/stateless.
package stateless

import (
	internal "github.com/bete7512/goauth/internal/modules/stateless"
	"github.com/bete7512/goauth/pkg/config"
)

// New creates a stateless JWT authentication module.
// Pass nil for cfg to use safe defaults (refresh token rotation enabled).
// To provide custom storage, set cfg.CustomStorage.
func New(cfg *config.StatelessModuleConfig) config.Module {
	return internal.New(cfg)
}
