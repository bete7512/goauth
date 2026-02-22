// Package twofactor exposes the two-factor authentication module.
// Import this package instead of internal/modules/twofactor.
package twofactor

import (
	internal "github.com/bete7512/goauth/internal/modules/twofactor"
	"github.com/bete7512/goauth/pkg/config"
)

// New creates a two-factor authentication module.
// cfg is variadic; pass zero args for safe defaults (Issuer:"GoAuth", 10 backup codes, length 8).
func New(cfg ...*config.TwoFactorConfig) config.Module {
	return internal.New(cfg...)
}
