# GoAuth

[![Go Report Card](https://goreportcard.com/badge/github.com/bete7512/goauth)](https://goreportcard.com/report/github.com/bete7512/goauth)
[![Go Version](https://img.shields.io/github/go-mod/go-version/bete7512/goauth)](https://go.dev/)
[![License](https://img.shields.io/github/license/bete7512/goauth)](LICENSE)

A modular, framework-agnostic authentication library for Go. Compose the auth features you need — session or stateless JWT, 2FA, OAuth, notifications, admin — and plug them into any web framework.

Module path: `github.com/bete7512/goauth` · Go 1.25

## Installation

```bash
go get github.com/bete7512/goauth
```

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
    "github.com/bete7512/goauth/pkg/types"
    "github.com/bete7512/goauth/storage"
)

func main() {
    // 1. Create storage
    store, err := storage.NewGormStorage(storage.GormConfig{
        Dialect:      types.DialectTypePostgres,
        DSN:          "host=localhost user=postgres password=secret dbname=authdb sslmode=disable",
        MaxOpenConns: 25,
        MaxIdleConns: 5,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close()

    // 2. Create auth instance (core module is auto-registered)
    a, err := auth.New(&config.Config{
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
    if err != nil {
        log.Fatal(err)
    }
    defer a.Close()

    // 3. Register optional modules (before Initialize)
    // If no auth module is registered, stateless JWT is the default.

    // 4. Initialize
    if err := a.Initialize(context.Background()); err != nil {
        log.Fatal(err)
    }

    // 5. Register routes and serve
    mux := http.NewServeMux()
    stdhttp.Register(mux, a)
    log.Println("Server running on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Architecture

### Three-Phase Lifecycle

```
auth.New(config) → auth.Use(module) → auth.Initialize(ctx)
```

`Use()` panics after `Initialize()` — modules are registered in order before initialization wires everything together.

### Package Layout

```
pkg/       Public contracts (auth, config, models, types, adapters)
internal/  Implementation (modules, events, middleware, security)
storage/   Storage backends (GORM built-in, cache decorators)
```

### Storage

Type-safe storage hierarchy. No string-based lookups.

```
types.Storage
  ├── Core()          → Users, Tokens, ExtendedAttributes
  ├── Session()       → Sessions
  ├── Stateless()     → Blacklist
  ├── Admin()
  ├── OAuth()         → Accounts
  ├── TwoFactorAuth() → TwoFactor, BackupCodes
  └── AuditLog()      → AuditLogs
```

GORM supports PostgreSQL, MySQL, and SQLite out of the box. You can also pass an existing `*gorm.DB`:

```go
store := storage.NewGormStorageFromDB(existingDB)
```

Or implement `types.Storage` for your own backend.

## Modules

### Core (Auto-Registered)

User registration, profile management, password reset/change, email & phone verification, availability checks.

### Authentication (Pick One)

Session and stateless are **mutually exclusive**. Registering both panics. If neither is registered, stateless is the default.

**Session** — Server-side sessions with cookie strategies, session management (list/revoke), sliding expiration.

```go
import "github.com/bete7512/goauth/internal/modules/session"

a.Use(session.New(&config.SessionModuleConfig{
    EnableSessionManagement: true,
    Strategy:                types.SessionStrategyCookieCache,
    CookieCacheTTL:          5 * time.Minute,
    SlidingExpiration:       true,
}, nil))
```

**Stateless** — JWT access + refresh tokens with refresh token rotation.

```go
import "github.com/bete7512/goauth/internal/modules/stateless"

a.Use(stateless.New(&config.StatelessModuleConfig{
    RefreshTokenRotation: true,
}, nil))
```

### Notification

Email/SMS delivery with pluggable senders and customizable branding & templates. Hooks into core events (signup, password reset, login alerts, etc.) — no HTTP routes.

```go
import "github.com/bete7512/goauth/internal/modules/notification"

a.Use(notification.New(&notification.Config{
    EmailSender:              senders.NewSendGridEmailSender(&senders.SendGridConfig{
        APIKey:      "your-api-key",
        DefaultFrom: "noreply@yourapp.com",
    }),
    EnableWelcomeEmail:       true,
    EnablePasswordResetEmail: true,
    EnableLoginAlerts:        true,
}))
```

### Two-Factor Authentication

TOTP-based 2FA with backup codes. Setup, verify, disable, and status endpoints.

```go
import "github.com/bete7512/goauth/internal/modules/twofactor"

a.Use(twofactor.New(&twofactor.TwoFactorConfig{
    Issuer:           "MyApp",
    Required:         false,
    BackupCodesCount: 10,
}))
```

### OAuth

Social login with providers: Google, GitHub, Facebook, Microsoft, Apple, Discord.

### Admin

Admin-only endpoints for user CRUD (list, get, update, delete). Protected by admin middleware.

### Audit

Logs security-relevant events for compliance and debugging.

### Captcha

reCAPTCHA v3 or Cloudflare Turnstile. Applied to specific routes by name.

```go
import "github.com/bete7512/goauth/internal/modules/captcha"

a.Use(captcha.New(&captcha.CaptchaConfig{
    Provider:           "google",
    RecaptchaSiteKey:   "your-site-key",
    RecaptchaSecretKey: "your-secret-key",
    ApplyToRoutes:      []string{"core.signup", "core.login"},
}))
```

### CSRF

Token-based CSRF protection for state-changing requests.

```go
import "github.com/bete7512/goauth/internal/modules/csrf"

a.Use(csrf.New(&csrf.CSRFConfig{
    TokenLength:      32,
    TokenExpiry:      3600,
    Secure:           true,
    ProtectedMethods: []string{"POST", "PUT", "DELETE", "PATCH"},
}))
```

### Magic Link

Passwordless authentication via email.

## Framework Integration

GoAuth provides adapters in `pkg/adapters/` for one-line route registration:

### Standard `net/http`

```go
import "github.com/bete7512/goauth/pkg/adapters/stdhttp"

mux := http.NewServeMux()
stdhttp.Register(mux, a)
http.ListenAndServe(":8080", mux)
```

### Gin

```go
import "github.com/bete7512/goauth/pkg/adapters/ginadapter"

r := gin.Default()
ginadapter.Register(r, a)
r.Run(":8080")
```

### Chi

```go
import "github.com/bete7512/goauth/pkg/adapters/chiadapter"

r := chi.NewRouter()
chiadapter.Register(r, a)
http.ListenAndServe(":8080", r)
```

### Fiber

```go
import "github.com/bete7512/goauth/pkg/adapters/fiberadapter"

app := fiber.New()
fiberadapter.Register(app, a)
app.Listen(":8080")
```

## Event System

Subscribe to events for custom logic:

```go
a.On(types.EventAfterSignup, func(ctx context.Context, e *types.Event) error {
    log.Printf("User signed up: %+v", e.Data)
    return nil
})

a.On(types.EventAfterLogin, func(ctx context.Context, e *types.Event) error {
    log.Printf("User logged in: %+v", e.Data["user"])
    return nil
})
```

Events are processed asynchronously with a built-in worker pool. For distributed systems, provide a custom `types.AsyncBackend` (Redis, RabbitMQ, Kafka, etc.).

## Configuration

```go
&config.Config{
    Storage:     store,
    AutoMigrate: true,
    BasePath:    "/api/v1",

    Security: types.SecurityConfig{
        JwtSecretKey:  "secret-32-chars-minimum!!!!",
        EncryptionKey: "encrypt-32-chars-minimum!!!",
        Session: types.SessionConfig{
            AccessTokenTTL:  15 * time.Minute,
            RefreshTokenTTL: 7 * 24 * time.Hour,
        },
    },

    Core: &config.CoreConfig{
        RequireEmailVerification: true,
        RequirePhoneVerification: false,
        RequireUserName:          false,
        RequirePhoneNumber:       false,
        UniquePhoneNumber:        true,
    },

    FrontendConfig: &config.FrontendConfig{
        URL:                     "http://localhost:3000",
        Domain:                  "localhost",
        ResetPasswordPath:       "/reset-password",
        VerifyEmailCallbackPath: "/verify-email",
    },

    CORS: &config.CORSConfig{
        Enabled:        true,
        AllowedOrigins: []string{"http://localhost:3000"},
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
    },
}
```

## Testing

```bash
make test              # Unit tests
make test-verbose      # Verbose output
make test-core         # Core module only
make test-session      # Session module only
make test-events       # Events only
make test-integration  # Integration (requires GOAUTH_TEST_DSN)
make test-coverage     # Coverage report
make mocks             # Regenerate mocks
make build             # Build
make lint              # Lint (golangci-lint)
```

## Creating Custom Modules

```bash
cd internal/modules
./new_module_with_route.sh mymodule      # Module with routes
./new_module_with_no_route.sh mymodule   # Middleware-only module
```

Every module implements `config.Module` (8 methods): `Name`, `Init`, `Routes`, `Middlewares`, `Models`, `RegisterHooks`, `Dependencies`, `SwaggerSpec`.

Reference: `internal/modules/core/module.go`.

## Documentation

- [Module docs](internal/modules/README.md)
- [Examples](examples/)
- [API docs](docs/)
- [Demo app](demo/) — Next.js frontend

## Contributing

Contributions are welcome. Here's how:

1. Fork the repository
2. Create a branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run `make build` and `make test` to verify
5. Commit and push
6. Open a pull request

Please follow the existing code patterns — exported interface / unexported struct for services, `types.GoAuthError` for error returns, dot-notation route names, and embedded swagger specs per module.

If you're adding a new module, use the scaffolding scripts in `internal/modules/` and follow the `config.Module` interface.

## License

MIT License — see [LICENSE](LICENSE) for the full text.

Copyright (c) 2025 bete7512
