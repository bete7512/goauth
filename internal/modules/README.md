# GoAuth Modules

This document describes the modular architecture and how to register modules.

## Architecture

GoAuth follows a three-phase lifecycle:

```
auth.New(config) → auth.Use(module) → auth.Initialize(ctx)
```

Every module implements `config.Module` (8 methods): `Name`, `Init`, `Routes`, `Middlewares`, `Models`, `RegisterHooks`, `Dependencies`, `SwaggerSpec`.

Modules are registered with `auth.Use()` before `auth.Initialize()`. Order is enforced — calling `Use()` after `Initialize()` panics.

Reference implementation: `core/module.go`.

---

## Core Module

Auto-registered by `auth.New`. Provides user registration, profile management, password reset/change, email & phone verification, and availability checks.

Core does **not** handle login/logout/refresh — those are handled by the Session or Stateless module.

---

## Authentication Modules

Session and Stateless are **mutually exclusive**. Registering both panics. If neither is registered, Stateless is used as the default.

### Session Module

Server-side sessions with cookie strategies, session management (list/revoke), and sliding expiration.

```go
import "github.com/bete7512/goauth/internal/modules/session"

a.Use(session.New(&config.SessionModuleConfig{
    EnableSessionManagement: true,
    Strategy:                types.SessionStrategyCookieCache,
    CookieCacheTTL:          5 * time.Minute,
    SlidingExpiration:       true,
}, nil))
```

Provides: login, logout, refresh, session list, session get, session delete, session delete-all.

### Stateless Module

JWT access + refresh tokens with refresh token rotation.

```go
import "github.com/bete7512/goauth/internal/modules/stateless"

a.Use(stateless.New(&config.StatelessModuleConfig{
    RefreshTokenRotation: true,
}, nil))
```

Provides: login, logout, refresh.

---

## Notification Module

Email/SMS delivery with pluggable senders and customizable branding & templates. Hooks into core events (signup, password reset, login alerts) — no HTTP routes.

```go
import "github.com/bete7512/goauth/internal/modules/notification"

a.Use(notification.New(&notification.Config{
    EmailSender:              senders.NewSendGridEmailSender(&senders.SendGridConfig{
        APIKey:      "your-api-key",
        DefaultFrom: "noreply@yourapp.com",
    }),
    Branding: &templates.Branding{...},
    EnableWelcomeEmail:       true,
    EnablePasswordResetEmail: true,
    EnableLoginAlerts:        true,
}))
```

---

## Two-Factor Authentication

TOTP-based 2FA with backup codes. Provides setup, verify, disable, and status endpoints.

```go
import "github.com/bete7512/goauth/internal/modules/twofactor"

a.Use(twofactor.New(&twofactor.TwoFactorConfig{
    Issuer:           "MyApp",
    Required:         false,
    BackupCodesCount: 10,
    CodeLength:       8,
}))
```

---

## Captcha Protection

reCAPTCHA v3 or Cloudflare Turnstile. Applied to specific routes by name.

```go
import "github.com/bete7512/goauth/internal/modules/captcha"

a.Use(captcha.New(&captcha.CaptchaConfig{
    Provider:           "google",
    RecaptchaSiteKey:   "your-site-key",
    RecaptchaSecretKey: "your-secret-key",
    RecaptchaThreshold: 0.5,
    ApplyToRoutes:      []string{"core.signup", "core.login"},
}))
```

---

## CSRF Protection

Token-based CSRF protection for state-changing requests.

```go
import "github.com/bete7512/goauth/internal/modules/csrf"

a.Use(csrf.New(&csrf.CSRFConfig{
    TokenLength:      32,
    TokenExpiry:      3600,
    Secure:           true,
    HTTPOnly:         true,
    SameSite:         http.SameSiteStrictMode,
    ProtectedMethods: []string{"POST", "PUT", "DELETE", "PATCH"},
}))
```

---

## Admin Module

Admin-only endpoints for user CRUD (list, get, update, delete). Protected by admin middleware.

```go
import "github.com/bete7512/goauth/internal/modules/admin"

a.Use(admin.New(nil, nil))
```

---

## OAuth Module

Social login with providers: Google, GitHub, Facebook, Microsoft, Apple, Discord.

---

## Magic Link Module

Passwordless authentication via email.

---

## Audit Module

Logs security-relevant events for compliance and debugging.

---

## Complete Example

```go
package main

import (
    "context"
    "log"
    "net/http"
    "time"

    "github.com/bete7512/goauth/internal/modules/captcha"
    "github.com/bete7512/goauth/internal/modules/csrf"
    "github.com/bete7512/goauth/internal/modules/twofactor"
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
        Storage:     store,
        AutoMigrate: true,
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

    // Stateless auth is the default — no need to register explicitly

    a.Use(twofactor.New(&twofactor.TwoFactorConfig{
        Issuer:           "MyApp",
        BackupCodesCount: 10,
    }))

    a.Use(captcha.New(&captcha.CaptchaConfig{
        Provider:           "cloudflare",
        TurnstileSiteKey:   "your-site-key",
        TurnstileSecretKey: "your-secret-key",
        ApplyToRoutes:      []string{"core.signup", "core.login"},
    }))

    a.Use(csrf.New(&csrf.CSRFConfig{
        TokenLength:      32,
        TokenExpiry:      3600,
        Secure:           false,
        HTTPOnly:         true,
        SameSite:         http.SameSiteStrictMode,
        ProtectedMethods: []string{"POST", "PUT", "DELETE", "PATCH"},
    }))

    if err := a.Initialize(context.Background()); err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    stdhttp.Register(mux, a)

    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

---

## Module Scaffolding

```bash
cd internal/modules
./new_module_with_route.sh mymodule      # Module with routes
./new_module_with_no_route.sh mymodule   # Middleware-only module
```

---

## Testing

```bash
make test           # All unit tests
make test-core      # Core module
make test-session   # Session module
make test-events    # Events
make test-verbose   # Verbose output
make mocks          # Regenerate mocks
make build          # Build
```
