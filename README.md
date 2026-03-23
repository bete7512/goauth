# GoAuth

[![Go Report Card](https://goreportcard.com/badge/github.com/bete7512/goauth)](https://goreportcard.com/report/github.com/bete7512/goauth)
[![Go Version](https://img.shields.io/github/go-mod/go-version/bete7512/goauth)](https://go.dev/)
[![License](https://img.shields.io/github/license/bete7512/goauth)](LICENSE)

A modular, framework-agnostic authentication library for Go. Compose the auth features you need — session or stateless JWT, 2FA, OAuth, notifications, admin — and drop it into any web framework.

Module path: `github.com/bete7512/goauth` · Go 1.25

---

## Installation

```bash
go get github.com/bete7512/goauth
```

---

## Quick Start

```go
package main

import (
    "context"
    "log"
    "net/http"
    "time"

    "github.com/bete7512/goauth/pkg/adapters/stdhttp"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/modules/session"
    "github.com/bete7512/goauth/pkg/types"
    "github.com/bete7512/goauth/storage"
)

func main() {
    // 1. Storage
    store, err := storage.NewGormStorage(storage.GormConfig{
        Dialect: types.DialectTypePostgres,
        DSN:     "host=localhost user=postgres password=secret dbname=authdb sslmode=disable",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close()

    // 2. Auth instance (core module is auto-registered)
    a, err := auth.New(&config.Config{
        Storage:  store,
        BasePath: "/api/v1",
        Migration: config.MigrationConfig{
            Auto: true, // apply pending migrations on startup
        },
        Security: types.SecurityConfig{
            JwtSecretKey:  "your-secret-key-min-32-chars!!",
            EncryptionKey: "your-encryption-key-32-chars!!!",
            Session: types.SessionConfig{
                AccessTokenTTL:  15 * time.Minute,
                RefreshTokenTTL: 7 * 24 * time.Hour,
            },
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    defer a.Close()

    // 3. Register optional modules (must be before Initialize)
    a.Use(session.New(&config.SessionModuleConfig{
        EnableSessionManagement: true,
    }, nil))

    // 4. Initialize
    if err := a.Initialize(context.Background()); err != nil {
        log.Fatal(err)
    }

    // 5. Mount routes and serve
    mux := http.NewServeMux()
    stdhttp.Register(mux, a)
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

---

## Lifecycle

```
auth.New(config) → auth.Use(module...) → auth.Initialize(ctx)
```

`Use()` panics after `Initialize()`. Modules register in order — dependencies must be registered before dependents.

---

## Storage

Type-safe storage hierarchy backed by GORM (PostgreSQL, MySQL, SQLite). Pass an existing `*gorm.DB` or implement `types.Storage` for a custom backend.

```go
// Built-in GORM storage
store, err := storage.NewGormStorage(storage.GormConfig{
    Dialect: types.DialectTypePostgres,
    DSN:     "...",
})

// From existing connection
store := storage.NewGormStorageFromDB(existingDB)
```

```
types.Storage
  ├── Core()          → Users, Tokens, ExtendedAttributes
  ├── Session()       → Sessions
  ├── OAuth()         → Accounts
  ├── TwoFactorAuth() → TwoFactor, BackupCodes
  └── AuditLog()      → AuditLogs
```

---

## Migrations

GoAuth ships embedded, per-dialect SQL migrations for each module. Two modes:

**Auto-apply on startup** — runs pending migrations and records them in a `goauth_migrations` tracking table:

```go
Migration: config.MigrationConfig{Auto: true}
```

**Generate SQL files for manual review** — writes one combined `goauth_{timestamp}_up.sql` and `goauth_{timestamp}_down.sql` containing only the modules not yet tracked:

```go
Migration: config.MigrationConfig{OutputDir: "./migrations"}
```

Both can be combined. Check migration status at runtime:

```go
records, err := a.MigrationStatus(ctx)
```

Supported dialects: `postgres`, `mysql`, `sqlite`.

---

## Modules

### Core (auto-registered)

Signup, profile (`/me`, update), password reset & change, email/phone verification, username/email availability checks.

### Authentication — pick one

Session and stateless are **mutually exclusive**. Registering both panics. If neither is registered, stateless JWT is the default.

**Session-based** — server-side sessions, cookie strategies, session management (list/revoke), sliding expiration:

```go
import "github.com/bete7512/goauth/pkg/modules/session"

a.Use(session.New(&config.SessionModuleConfig{
    EnableSessionManagement: true,
    Strategy:                types.SessionStrategyCookieCache,
    CookieCacheTTL:          5 * time.Minute,
    SlidingExpiration:       true,
}, nil))
```

**Stateless JWT** — access + refresh tokens with optional rotation:

```go
import "github.com/bete7512/goauth/pkg/modules/stateless"

a.Use(stateless.New(&config.StatelessModuleConfig{
    RefreshTokenRotation: true,
}, nil))
```

### Notification

Email/SMS delivery with pluggable senders. Hooks into core events (signup, password reset, login alerts). No HTTP routes.

```go
import (
    "github.com/bete7512/goauth/pkg/modules/notification"
    "github.com/bete7512/goauth/pkg/modules/notification/senders"
)

a.Use(notification.New(&notification.Config{
    EmailSender: senders.NewSendGridEmailSender(&senders.SendGridConfig{
        APIKey:      "SG.xxx",
        DefaultFrom: "noreply@yourapp.com",
    }),
    EnableWelcomeEmail:       true,
    EnablePasswordResetEmail: true,
    EnableLoginAlerts:        true,
}))
```

Built-in senders: SendGrid, Twilio. Implement `notification.EmailSender` or `notification.SMSSender` for custom providers.

### Two-Factor Authentication

TOTP + backup codes. Endpoints: setup, verify, disable, status.

```go
import "github.com/bete7512/goauth/pkg/modules/twofactor"

a.Use(twofactor.New(&config.TwoFactorConfig{
    Issuer:           "MyApp",
    Required:         false,
    BackupCodesCount: 10,
}, nil))
```

### OAuth

Social login: Google, GitHub, Facebook, Microsoft, Apple, Discord.

```go
import "github.com/bete7512/goauth/pkg/modules/oauth"

a.Use(oauth.New(&config.OAuthModuleConfig{
    Providers: map[string]*config.OAuthProviderConfig{
        "google": {
            ClientID:     "your-client-id",
            ClientSecret: "your-client-secret",
            Scopes:       []string{"openid", "email", "profile"},
        },
    },
    DefaultRedirectURL: "http://localhost:3000/auth/callback",
    AllowSignup:        true,
}, nil))
```

### Admin

User CRUD (list, get, update, delete) behind admin middleware. Audit log cleanup endpoint.

```go
import "github.com/bete7512/goauth/pkg/modules/admin"

a.Use(admin.New(nil, nil))
```

### Audit

Records security-relevant events (login, logout, password change, etc.) for compliance and debugging.

### Captcha

reCAPTCHA v3 or Cloudflare Turnstile, applied to specific routes by name.

```go
import "github.com/bete7512/goauth/pkg/modules/captcha"

a.Use(captcha.New(&config.CaptchaModuleConfig{
    Provider:       types.CaptchaProviderGoogle,
    SiteKey:        "your-site-key",
    SecretKey:      "your-secret-key",
    ApplyToRoutes:  []types.RouteName{types.RouteSignup, types.RouteLogin},
}, nil))
```

### CSRF

Token-based CSRF protection for state-changing requests.

```go
import "github.com/bete7512/goauth/pkg/modules/csrf"

a.Use(csrf.New(&config.CSRFModuleConfig{
    TokenExpiry:      time.Hour,
    Secure:           true,
    ProtectedMethods: []string{"POST", "PUT", "DELETE", "PATCH"},
}))
```

### Magic Link

Passwordless authentication via email.

---

## Framework Adapters

One-line route registration for common frameworks:

```go
// net/http
stdhttp.Register(mux, a)

// Gin
ginadapter.Register(router, a)

// Chi
chiadapter.Register(router, a)

// Fiber
fiberadapter.Register(app, a)
```

All adapters live in `pkg/adapters/`.

---

## Event System

Subscribe to events for custom business logic:

```go
a.On(types.EventAfterSignup, func(ctx context.Context, e *types.Event) error {
    // send welcome email, set up trial, etc.
    return nil
})

a.On(types.EventAfterLogin, func(ctx context.Context, e *types.Event) error {
    // analytics, rate limiting, etc.
    return nil
})
```

Async events are processed by a built-in worker pool (10 workers, 1000 queue). For distributed systems, provide a custom `types.AsyncBackend`:

```go
a, _ := auth.New(&config.Config{
    AsyncBackend: myRedisBackend, // implements types.AsyncBackend
})
```

Key events: `EventAfterSignup`, `EventAfterLogin`, `EventAfterLogout`, `EventBeforeLogin`, `EventAfterPasswordVerified`, `EventSendPasswordResetEmail`, `EventAfterEmailVerified`, `EventAuthLoginSuccess`.

---

## Protecting Routes

```go
mux.Handle("/api/v1/dashboard", a.RequireAuth(dashboardHandler))
```

`RequireAuth` validates the JWT and injects `user_id` (and `session_id` if session-based) into the request context:

```go
userID := r.Context().Value(types.UserIDKey).(string)
```

---

## Configuration Reference

```go
&config.Config{
    Storage:  store,
    BasePath: "/api/v1",                // default: "/auth"
    APIURL:   "https://api.example.com",

    Migration: config.MigrationConfig{
        Auto:      true,        // apply on startup
        OutputDir: "./sql",     // write SQL files (can combine with Auto)
    },

    Security: types.SecurityConfig{
        JwtSecretKey:  "min-32-chars",
        EncryptionKey: "min-32-chars",
        HashSaltLength: 10,
        Session: types.SessionConfig{
            Name:            "session_token",
            AccessTokenTTL:  15 * time.Minute,
            RefreshTokenTTL: 7 * 24 * time.Hour,
            SessionTTL:      30 * 24 * time.Hour,
        },
        PasswordPolicy: types.PasswordPolicy{
            MinLength:        8,
            RequireUppercase: true,
            RequireSpecial:   true,
        },
    },

    Core: &config.CoreConfig{
        RequireEmailVerification: true,
        RequirePhoneVerification: false,
        RequireUserName:          false,
        UniquePhoneNumber:        true,
    },

    FrontendConfig: &config.FrontendConfig{
        URL:                     "https://app.example.com",
        Domain:                  "example.com",
        ResetPasswordPath:       "/reset-password",
        VerifyEmailCallbackPath: "/verify-email",
    },

    CORS: &config.CORSConfig{
        Enabled:        true,
        AllowedOrigins: []string{"https://app.example.com"},
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
        AllowedHeaders: []string{"Content-Type", "Authorization"},
    },

    Logger: myLogger, // implements types.Logger; defaults to logrus
}
```

---

## Custom Modules

Implement `config.Module` (8 methods) and register with `auth.Use()`:

```go
type config.Module interface {
    Name()          string
    Init(ctx, deps) error
    Routes()        []config.RouteInfo
    Middlewares()   []config.MiddlewareConfig
    RegisterHooks(events types.EventBus) error
    Dependencies()  []string
    OpenAPISpecs()  []byte
    Migrations()    types.ModuleMigrations
}
```

Pattern: exported interface + unexported struct + constructor. Include a compile-time check:

```go
var _ config.Module = (*MyModule)(nil)
```

Reference implementation: [internal/modules/core/module.go](internal/modules/core/module.go)

---

## Development

```bash
make build          # compile
make test           # unit tests
make test-core      # core module only
make test-session   # session module only
make test-coverage  # coverage report
make mocks          # regenerate mocks (uber/mock)
make lint           # golangci-lint
make test-integration  # needs GOAUTH_TEST_DSN env var
```

---

## License

MIT — see [LICENSE](LICENSE).

Copyright (c) 2025 bete7512
