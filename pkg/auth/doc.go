// Package auth is the entry point of GoAuth, an authentication library for Go.
//
// GoAuth adds user accounts to a Go application without running a separate
// service: sign-up and login, JWT or server-side sessions, email verification
// and password reset, OAuth2 social login, passkeys (WebAuthn), two-factor
// authentication (TOTP), magic links, organizations, role-based access control,
// SAML single sign-on, an OpenID Connect provider and an admin console. Users
// are stored in your own PostgreSQL, MySQL or SQLite database.
//
// Setup has three phases, in this order:
//
//	a, err := auth.New(&config.Config{...}) // configure
//	err = a.Use(twofactor.New(...))         // register optional modules
//	err = a.Initialize(ctx)                 // migrate, wire and start
//
// Then mount the routes with an adapter (net/http, Gin, Chi or Fiber) and
// protect your own handlers with a.RequireAuth.
//
// Documentation and guides: https://goauth.beteg.dev/docs
package auth
