---
id: showcase
title: Examples
sidebar_label: Examples
description: GoAuth usage examples
---

# Examples

## Basic Authentication

Minimal setup with Core module and stateless JWT (default):

```go
import (
    "context"
    "net/http"

    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/types"
    "github.com/bete7512/goauth/pkg/adapters/stdhttp"
    "github.com/bete7512/goauth/storage/gorm"
)

store, _ := storage.NewGormStorage(storage.GormConfig{
    Dialect: types.DialectTypeSqlite,
    DSN:     "auth.db",
})

a, _ := auth.New(&config.Config{
    Storage: store,
    Migration: config.MigrationConfig{Auto: true},
    Security: types.SecurityConfig{
        JwtSecretKey:  "your-secret-key-min-32-chars!!",
        EncryptionKey: "your-encryption-key-32-chars!!",
    },
})

a.Initialize(context.Background())

mux := http.NewServeMux()
stdhttp.Register(mux, a)
http.ListenAndServe(":8080", mux)
```

---

## Session-Based Auth

Server-side sessions with cookie-cache strategy:

```go
import "github.com/bete7512/goauth/pkg/modules/session"

a.Use(session.New(&config.SessionModuleConfig{
    EnableSessionManagement: true,
    Strategy:                types.SessionStrategyCookieCache,
    CookieCacheTTL:          5 * time.Minute,
    SlidingExpiration:       true,
}, nil))
```

---

## With Notifications

Add email notifications for signup, password reset, and login alerts:

```go
import (
    "github.com/bete7512/goauth/pkg/modules/notification"
    "github.com/bete7512/goauth/pkg/modules/notification/senders"
)

a.Use(notification.New(&notification.Config{
    EmailSender: senders.NewSendGridEmailSender(&senders.SendGridConfig{
        APIKey:      "SG.xxxxx",
        DefaultFrom: "noreply@yourapp.com",
    }),
    EnableWelcomeEmail:       true,
    EnablePasswordResetEmail: true,
    EnableLoginAlerts:        true,
}))
```

---

## With Two-Factor Auth

TOTP-based 2FA with backup codes:

```go
import "github.com/bete7512/goauth/pkg/modules/twofactor"

a.Use(twofactor.New(&config.TwoFactorConfig{
    Issuer:           "MyApp",
    BackupCodesCount: 10,
    CodeLength:       8,
}))
```

---

## Full Setup

All modules together:

```go
import (
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/types"
    "github.com/bete7512/goauth/pkg/adapters/ginadapter"
    "github.com/bete7512/goauth/pkg/modules/admin"
    "github.com/bete7512/goauth/pkg/modules/notification"
    "github.com/bete7512/goauth/pkg/modules/twofactor"
    "github.com/bete7512/goauth/pkg/modules/captcha"
    "github.com/bete7512/goauth/pkg/modules/csrf"
    "github.com/bete7512/goauth/pkg/modules/organization"
)

a, _ := auth.New(&config.Config{
    Storage:  store,
    Migration: config.MigrationConfig{Auto: true},
    BasePath: "/api/v1",
    Security: types.SecurityConfig{
        JwtSecretKey:  os.Getenv("JWT_SECRET_KEY"),
        EncryptionKey: os.Getenv("ENCRYPTION_KEY"),
        Session: types.SessionConfig{
            AccessTokenTTL:  15 * time.Minute,
            RefreshTokenTTL: 7 * 24 * time.Hour,
        },
    },
    Core: &config.CoreConfig{
        RequireEmailVerification: true,
    },
})

a.Use(notification.New(&notification.Config{...}))
a.Use(twofactor.New(&config.TwoFactorConfig{...}))
a.Use(captcha.New(&config.CaptchaModuleConfig{...}))
a.Use(csrf.New(&config.CSRFModuleConfig{...}))
a.Use(admin.New(nil))
a.Use(organization.New(nil))

a.Initialize(context.Background())

r := gin.Default()
ginadapter.Register(r, a)
r.Run(":8080")
```

---

## Demo App

A Next.js demo frontend is included in the `demo/` directory. See the [demo README](https://github.com/bete7512/goauth/tree/main/demo) for setup.
