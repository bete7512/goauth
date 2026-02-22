// Package captcha exposes the CAPTCHA verification module.
// Import this package instead of internal/modules/captcha.
package captcha

import (
	internal "github.com/bete7512/goauth/internal/modules/captcha"
	"github.com/bete7512/goauth/pkg/config"
)

// New creates a CAPTCHA verification module.
func New(cfg *config.CaptchaModuleConfig) config.Module {
	return internal.New(cfg)
}
