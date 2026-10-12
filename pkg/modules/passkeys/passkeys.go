// Package passkeys exposes the WebAuthn/Passkeys module.
// Import this package instead of internal/modules/passkeys.
package passkeys

import (
	internal "github.com/bete7512/goauth/internal/modules/passkeys"
	"github.com/bete7512/goauth/pkg/config"
)

// Config is the user-facing configuration for the passkeys module.
type Config = config.PasskeysModuleConfig

// New creates a passkeys module. RPID and at least one RPOrigin are required.
func New(cfg *Config) config.Module {
	return internal.New(cfg)
}
