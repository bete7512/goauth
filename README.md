<div align="center">

# 🔐 GoAuth

**Authentication for Go, assembled from parts you actually need.**

[![Go Report Card](https://goreportcard.com/badge/github.com/bete7512/goauth)](https://goreportcard.com/report/github.com/bete7512/goauth)
[![Go Version](https://img.shields.io/github/go-mod/go-version/bete7512/goauth)](https://go.dev/)
[![License](https://img.shields.io/github/license/bete7512/goauth)](LICENSE)

[Docs](https://goauth.beteg.dev) · [Quick Start](#-quick-start) · [Modules](#-modules) · [Examples](./examples)

</div>

---

GoAuth is a **library, not a service**. You import it, plug in the modules you want, and mount the routes on the router you already use. Your database, your server, your users.

```
auth.New(config)  →  auth.Use(modules...)  →  auth.Initialize(ctx)
```

That's the whole mental model.

## ✨ Why GoAuth

- **Lego-style modules.** Start with signup and login. Add 2FA, OAuth, passkeys, or organizations later with one line each.
- **Any framework.** Adapters for `net/http`, Gin, Chi, and Fiber. Everything else works through plain `http.Handler`.
- **Your database.** PostgreSQL, MySQL, or SQLite through GORM, with embedded migrations per module.
- **Secure by default.** bcrypt password hashing, account lockout, request rate limiting, refresh-token rotation, hashed refresh tokens, 2FA attempt lockout, and AES-256-GCM encryption.
- **Hookable.** Every important moment fires an event you can subscribe to.
- **Typed client for free.** Each module ships an OpenAPI spec, and a TypeScript client is generated from them.

## 📦 Install

```bash
go get github.com/bete7512/goauth
```

Requires Go 1.26+.

## 🚀 Quick Start

A working auth server in about 40 lines, using SQLite so there's nothing to set up:

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/bete7512/goauth/pkg/adapters/stdhttp"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/types"
    "github.com/bete7512/goauth/storage"
)

func main() {
    store, err := storage.NewGormStorage(storage.GormConfig{
        Dialect: types.DialectTypeSqlite,
        DSN:     "auth.db",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close()

    a, err := auth.New(&config.Config{
        Storage:   store,
        BasePath:  "/auth",
        Migration: config.MigrationConfig{Auto: true},
        Core:      &config.CoreConfig{},
        Security: types.SecurityConfig{
            JwtSecretKey:  "change-me-to-a-32-char-secret!!!",
            EncryptionKey: "change-me-to-a-32-char-key!!!!!!",
            // Cookies are Secure by default; allow plain HTTP only on localhost.
            Session: types.SessionConfig{AllowInsecureCookies: true},
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    defer a.Close()

    if err := a.Initialize(context.Background()); err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    mux.Handle("GET /hello", a.RequireAuth(http.HandlerFunc(hello)))

    log.Fatal(http.ListenAndServe(":8080", stdhttp.Register(mux, a)))
}

func hello(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value(types.UserIDKey).(string)
    w.Write([]byte("hello, " + userID))
}
```

Try it:

```bash
# sign up
curl -X POST localhost:8080/auth/signup \
  -d '{"email":"ada@example.com","password":"S3cure-pass!"}'

# log in and grab the access token
curl -X POST localhost:8080/auth/login \
  -d '{"email":"ada@example.com","password":"S3cure-pass!"}'

# call your protected route
curl localhost:8080/hello -H "Authorization: Bearer <access_token>"
```

You didn't register any modules, so GoAuth used its defaults. **Core** handles signup, profile, and passwords. **Stateless JWT** handles login, refresh with rotation, and logout.

## 🧩 Modules

Pick what you need. Each one brings its own routes, tables, and OpenAPI docs.

| Module | What it gives you |
|---|---|
| **Core** | Signup, profile, password reset and change, email and phone verification. Always on. |
| **Stateless** | JWT access and refresh tokens with rotation. The default when no auth mode is chosen. |
| **Session** | Server-side sessions, cookie strategies, sliding expiry, and listing or revoking devices. |
| **Notification** | Email and SMS through Resend, SendGrid, SMTP, or Twilio, with branded templates. |
| **Two-Factor** | TOTP authenticator apps plus backup codes. |
| **OAuth** | Google, GitHub, Microsoft, Discord, and any OIDC provider, with PKCE. |
| **Magic Link** | Passwordless login by email. |
| **Passkeys** | WebAuthn login with Touch ID, Face ID, Windows Hello, or security keys. |
| **Organization** | Multi-tenant orgs with members, roles, invitations, and org switching. |
| **Invitation** | Invite-only signups for apps without organizations. |
| **Admin** | User management endpoints behind admin middleware. |
| **Audit** | A security event trail covering logins, password changes, and more. |
| **Captcha** | reCAPTCHA v3 or Cloudflare Turnstile on the routes you choose. |
| **CSRF** | Double-submit cookie protection for state-changing requests. |
| **Rate Limit** | Per-IP and per-identifier budgets on login, verification, resets, sends, and signup. On by default, with a pluggable store for multiple replicas. |

> **Session and Stateless are mutually exclusive.** Choose one, or register neither to get Stateless.

### Adding modules

Each module is one `Use()` call made before `Initialize()`:

```go
import (
    "github.com/bete7512/goauth/pkg/modules/notification"
    "github.com/bete7512/goauth/pkg/modules/notification/senders"
    "github.com/bete7512/goauth/pkg/modules/oauth"
    "github.com/bete7512/goauth/pkg/modules/ratelimit"
    "github.com/bete7512/goauth/pkg/modules/session"
    "github.com/bete7512/goauth/pkg/modules/twofactor"
)

// Server-side sessions instead of stateless JWT
a.Use(session.New(&config.SessionModuleConfig{
    EnableSessionManagement: true,
    SlidingExpiration:       true,
}))

// Send real emails
a.Use(notification.New(&notification.Config{
    EmailSender: senders.NewResendEmailSender(&senders.ResendConfig{
        APIKey:      os.Getenv("RESEND_API_KEY"),
        DefaultFrom: "hello@yourapp.com",
    }),
    EnableWelcomeEmail: true,
}))

// "Sign in with Google"
a.Use(oauth.New(&config.OAuthModuleConfig{
    Providers: map[string]*config.OAuthProviderConfig{
        "google": {ClientID: "...", ClientSecret: "..."},
    },
    DefaultRedirectURL: "https://app.yourapp.com/auth/callback",
    AllowSignup:        true,
}))

// Authenticator-app 2FA
a.Use(twofactor.New(&config.TwoFactorConfig{Issuer: "YourApp"}))

// The rate limiter is on by default; tune it or turn it off
a.Use(ratelimit.New(&config.RateLimitModuleConfig{
    Allowlist: []string{"10.0.0.0/8"}, // never limit internal callers
}))
```

`Use()` returns an error when a module is duplicated, conflicts with another, or is missing a dependency. Always check it.

More recipes for passkeys, organizations, captcha, and the rest are on the [docs site](https://goauth.beteg.dev).

## 🔌 Bring Your Own Framework

```go
stdhttp.Register(mux, a)          // net/http
ginadapter.Register(router, a)    // Gin
chiadapter.Register(router, a)    // Chi
fiberadapter.Register(app, a)     // Fiber
```

Using something else? `a.Routes()` returns plain method, path, and handler triples you can wire up anywhere.

## 🪝 Hook Into Everything

React to auth events without forking anything:

```go
a.On(types.EventAfterSignup, func(ctx context.Context, e *types.Event) error {
    // start a trial, sync to your CRM, post to Slack...
    return nil
})
```

Events run on a built-in worker pool. For multi-instance deployments, pass your own `types.AsyncBackend` through config, such as NATS, Redis, or Kafka. The [example app](./examples) includes a NATS JetStream backend.

## 🗄️ Storage and Migrations

```go
store, _ := storage.NewGormStorage(storage.GormConfig{Dialect: types.DialectTypePostgres, DSN: dsn})
store    := storage.NewGormStorageFromDB(existingGormDB) // reuse your connection
```

Migrations are embedded per module and per dialect. You can apply them on startup, or write them to SQL files for review:

```go
Migration: config.MigrationConfig{
    Auto:      true,            // apply pending migrations at startup
    OutputDir: "./migrations",  // and/or write up/down SQL files
}
```

Need a different database? Implement `types.Storage`.

## 🔑 JWT Signing and JWKS

HS256 is the default. Switch to **RS256** or **ES256** so other services can verify tokens without sharing a secret:

```go
Security: types.SecurityConfig{
    JWTAlgorithm:      types.JWTAlgorithmRS256,
    JWTPrivateKeyFile: "/etc/goauth/jwt.key",
    // ...
}
```

The public keys are then served at `{BasePath}/.well-known/jwks.json`. Every token carries a `kid`, so key rotation is a config change.

## 🟦 TypeScript Client

Every module ships an OpenAPI spec. From those specs, GoAuth generates a typed fetch client, `@goauth/client`:

```bash
make sdk
```

See [`clients/ts`](./clients/ts) for details.

## 🛠️ Write Your Own Module

A module is any type that implements `config.Module`. That means a name, routes, middlewares, hooks, migrations, and an OpenAPI spec. It gets the same storage, events, logger, and security manager as the built-in ones.

```go
var _ config.Module = (*BillingModule)(nil)

a.Use(&BillingModule{})
```

The [core module](internal/modules/core/module.go) is the reference implementation.

## 🧪 Development

```bash
make build              # compile everything
make test               # unit tests
make test-integration   # full auth lifecycle against in-memory SQLite
make test-bench         # benchmarks
make lint               # golangci-lint
make mocks              # regenerate mocks
make check              # everything CI runs except the database contract tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for tooling, conventions and the release steps.

## 🗺️ Repository Map

```
pkg/        public API: auth, config, types, modules, adapters
internal/   module implementations, events, security
storage/    GORM backend and cache decorators
clients/ts  generated TypeScript client
examples/   a full server using most modules
demo/       Next.js demo app
docs/       documentation site
```

## 🚧 Status

GoAuth is **pre-1.0**. The first public beta, `v0.3.0-beta.1`, is prepared in the [First beta release](https://github.com/bete7512/goauth/milestone/1) milestone. Read the [CHANGELOG](CHANGELOG.md) for what changed since v0.2.1, and the [upgrade guide](docs/docs/upgrade.md#upgrading-from-v02x) before moving from v0.2.x.

| Area | State |
|---|---|
| Rate limiting on by default, pluggable store | Done (#18) |
| Phone codes bound to the account with attempt limits | Done (#19) |
| TOTP codes accepted once | Done (#20) |
| MySQL migrations | Done (#21) |
| Full `GET /me` profile | Done (#22) |
| Secure cookies by default | Done (#23) |
| Lockout that reveals nothing | Done (#24) |
| Single-use tokens and codes stored as digests | Done (#25) |
| OAuth sign-up requires a verified email | Done (#26) |
| Dependency advisories, Go 1.26 | Done (#31) |
| CI: lint, govulncheck, tidy and mock drift checks | Done (#27) |
| Release workflow, CHANGELOG, SECURITY.md, CONTRIBUTING | Done (#28) |
| Two-factor service tests, regression tests | #29 |
| Exported API docs, production checklist | #30 |
| OAuth links for unverified emails under the opt-in | #41 |

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## 📄 License

MIT. See [LICENSE](LICENSE).
