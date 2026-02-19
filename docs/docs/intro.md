---
id: intro
title: Introduction
sidebar_label: Introduction
slug: intro
---

# GoAuth

GoAuth is a modular, framework-agnostic authentication library for Go. It provides composable modules — core auth, session or stateless JWT, 2FA, OAuth, notifications, admin, audit — that you register and initialize with a three-phase pattern.

## How It Works

```
auth.New(config) → auth.Use(module) → auth.Initialize(ctx)
```

1. **Create** — `auth.New()` creates the auth instance and auto-registers the Core module
2. **Register** — `auth.Use()` adds optional modules (before Initialize)
3. **Initialize** — `auth.Initialize()` runs migrations, builds routes, wires hooks

After initialization, register routes with a framework adapter and start serving.

## Example

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
    "github.com/bete7512/goauth/pkg/types"
    "github.com/bete7512/goauth/storage"
)

func main() {
    store, _ := storage.NewGormStorage(storage.GormConfig{
        Dialect: types.DialectTypeSqlite,
        DSN:     "auth.db",
    })
    defer store.Close()

    a, _ := auth.New(&config.Config{
        Storage:     store,
        AutoMigrate: true,
        BasePath:    "/api/v1",
        Security: types.SecurityConfig{
            JwtSecretKey:  "your-secret-key-min-32-chars!!",
            EncryptionKey: "your-encryption-key-32-chars!!",
            Session: types.SessionConfig{
                AccessTokenTTL:  15 * time.Minute,
                RefreshTokenTTL: 7 * 24 * time.Hour,
            },
        },
    })
    defer a.Close()

    // Optional modules go here: a.Use(...)
    // If no auth module registered, stateless JWT is the default.

    a.Initialize(context.Background())

    mux := http.NewServeMux()
    stdhttp.Register(mux, a)
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Available Modules {#available-modules}

| Module | Description | Registration |
|--------|-------------|--------------|
| **Core** | Signup, profile, password reset/change, email/phone verification | Auto-registered |
| **Session** | Server-side sessions with cookie strategies | `session.New(...)` |
| **Stateless** | JWT access + refresh tokens | `stateless.New(...)` (default) |
| **Notification** | Email/SMS via SendGrid, SMTP, Twilio, Resend | `notification.New(...)` |
| **Two-Factor** | TOTP-based 2FA with backup codes | `twofactor.New(...)` |
| **OAuth** | Google, GitHub, Facebook, Microsoft, Apple, Discord | `oauth.New(...)` |
| **Admin** | User CRUD with admin middleware | `admin.New(...)` |
| **Audit** | Security event logging | `audit.New(...)` |
| **Captcha** | reCAPTCHA v3, Cloudflare Turnstile | `captcha.New(...)` |
| **CSRF** | Token-based CSRF protection | `csrf.New(...)` |
| **Magic Link** | Passwordless auth via email | `magiclink.New(...)` |

Session and Stateless are **mutually exclusive** — registering both panics.

## Framework Adapters

GoAuth provides adapters in `pkg/adapters/` for one-line route registration:

```go
// Standard net/http
stdhttp.Register(mux, a)

// Gin
ginadapter.Register(router, a)

// Chi
chiadapter.Register(router, a)

// Fiber
fiberadapter.Register(app, a)
```

## Event System

Subscribe to events for custom logic:

```go
a.On(types.EventAfterSignup, func(ctx context.Context, e *types.Event) error {
    log.Printf("New user: %+v", e.Data)
    return nil
})
```

Events are processed asynchronously. Custom async backends (Redis, RabbitMQ, Kafka) are supported.

## Storage

Type-safe storage hierarchy backed by GORM. Supports PostgreSQL, MySQL, SQLite.

```go
store, _ := storage.NewGormStorage(storage.GormConfig{
    Dialect:      types.DialectTypePostgres,
    DSN:          "host=localhost user=postgres password=secret dbname=authdb sslmode=disable",
    MaxOpenConns: 25,
    MaxIdleConns: 5,
})
```

You can also pass an existing `*gorm.DB` via `storage.NewGormStorageFromDB()`, or implement `types.Storage` for your own backend.

## Next Steps

- [Installation](installation.md) — Get GoAuth installed
- [Quick Start](quickstart.md) — Build your first auth system
- [Core Module](modules/core.md) — Core module details
- [API Reference](api/endpoints.md) — Endpoint documentation
