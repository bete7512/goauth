// Package ui exposes the server-rendered console module.
// Import this package instead of internal/modules/ui.
//
// The console is an admin interface for super admins (users, audit log,
// roles) served under BasePath + "/ui", and, with Config.UserPages, a
// sign-in and account page for everyone else:
//
//	a.Use(ui.New(nil))                          // admin console only
//	a.Use(ui.New(&ui.Config{UserPages: true}))  // plus pages for all users
//
// Pages appear for the modules that are registered: the audit log with the
// audit module, roles with the rbac module, the two-factor step with the
// twofactor module. The console signs in with the application's cookies, so
// Security.AuthMode must be "cookie" or "both".
package ui

import (
	internal "github.com/bete7512/goauth/internal/modules/ui"
	"github.com/bete7512/goauth/pkg/config"
)

// Config is the configuration for the ui module.
type Config = internal.Config

// DefaultPageSize is the number of rows a list page shows by default.
const DefaultPageSize = internal.DefaultPageSize

// New creates the ui module. Pass nil for the admin console only.
func New(cfg *Config) config.Module {
	return internal.New(cfg)
}
