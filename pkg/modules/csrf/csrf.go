// Package csrf exposes the CSRF protection module.
// Import this package instead of internal/modules/csrf.
package csrf

import (
	internal "github.com/bete7512/goauth/internal/modules/csrf"
	"github.com/bete7512/goauth/pkg/config"
)

// New creates a CSRF protection module.
func New(cfg *config.CSRFModuleConfig) config.Module {
	return internal.New(cfg)
}
