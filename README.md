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

Requires Go 1.25+.

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
```

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

## 🚧 Status and Road to the First Beta

GoAuth is **pre-release**. On `main` the build, unit, integration and race suites pass, the TypeScript client generates for both strategies, and the quick start above works end to end. It is not yet tagged beta: an assessment on 2026-10-25 found the items below. They are tracked in the [First beta release](https://github.com/bete7512/goauth/milestone/1) milestone.

### Release blockers

| # | Item | Issue |
|---|------|-------|
| 1 | Rate limiting module, on by default, with a pluggable store | #18 (implemented) |
| 2 | Attempt limits and account binding for phone reset and verification codes | #19 |
| 3 | TOTP replay prevention (store the last accepted time step) | #20 |
| 4 | MySQL support: migrations table index length, currently failing CI | #21 |
| 5 | `GET /me` returns a partial profile | #22 |
| 6 | Secure cookies by default | #23 (implemented) |
| 7 | Release workflow, CHANGELOG, SECURITY.md, CONTRIBUTING, version scheme | #28 |

### Hardening before beta

- Uniform lockout error and ordering: #24
- Single-use tokens stored as digests: #25
- OAuth signup requires a verified provider email: #26
- Dependency and toolchain updates (pgx advisory, x/text, tidy): #31

### CI, tests and docs

- CI: lint, govulncheck, tidy and mocks drift checks, Go version matrix, protected `main`: #27
- Tests: two-factor service suite and one regression test per blocker: #29
- Docs: correct stale claims, document the exported API, production checklist: #30

### Rate limiting plan (summary)

- A `ratelimit` module that `Initialize` registers for you when none is registered, the same way the stateless module becomes the default auth module today. Opt out with `Disabled`.
- Keys by client IP (trusted-proxy aware, IPv6 bucketed by /64) and by submitted identifier (hashed). Rules match route-name patterns. Defaults cover login, 2FA, passkeys, magic link, reset and verification, sends, signup, availability checks, refresh and OAuth.
- GCRA engine with an in-memory store by default and a `types.RateLimitStore` contract for Redis. Store errors fail open unless `FailClosed` is set.
- `429` with `Retry-After` and `RateLimit-*` headers, plus a `ratelimit.exceeded` event the audit module records.
- Full design and open decisions: #18.

### Release checklist

1. Close every `release-blocker` issue in the milestone.
2. CI green on `main`, including the MySQL and Postgres contract jobs, lint and govulncheck.
3. `CHANGELOG.md`, `SECURITY.md` and `CONTRIBUTING.md` in place, with an upgrade note for v0.2.x users (re-authentication, maintenance deployment).
4. Regenerate the TypeScript client (`make sdk`) and the docs site; make sure README claims match the code.
5. Tag `v0.3.0-beta.1` (or `v1.0.0-beta.1`) from `main`; `release.yml` marks it a pre-release; verify the module on pkg.go.dev.

## 📄 License

MIT. See [LICENSE](LICENSE).
