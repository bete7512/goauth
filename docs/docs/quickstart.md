---
id: quickstart
title: Quick Start
sidebar_label: Quick Start
sidebar_position: 3
---

# Quick Start

Build a working authentication system with GoAuth in a few minutes.

## Prerequisites

- Go 1.25+ installed
- GoAuth installed (see [Installation](installation.md))

## 1. Project Setup

```bash
mkdir goauth-demo
cd goauth-demo
go mod init goauth-demo
go get github.com/bete7512/goauth
```

## 2. Create main.go

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
    // 1. Create storage (SQLite for dev)
    store, err := storage.NewGormStorage(storage.GormConfig{
        Dialect: types.DialectTypeSqlite,
        DSN:     "auth.db",
    })
    if err != nil {
        log.Fatalf("Storage error: %v", err)
    }
    defer store.Close()

    // 2. Create auth instance (Core module auto-registered)
    a, err := auth.New(&config.Config{
        Storage:     store,
        AutoMigrate: true,
        BasePath:    "/api/v1",
        Security: types.SecurityConfig{
            JwtSecretKey:  "your-secret-key-min-32-chars!!!!",
            EncryptionKey: "your-encryption-key-32-chars!",
            Session: types.SessionConfig{
                AccessTokenTTL:  15 * time.Minute,
                RefreshTokenTTL: 7 * 24 * time.Hour,
            },
        },
        Core: &config.CoreConfig{
            RequireEmailVerification: false,
            RequirePhoneVerification: false,
        },
    })
    if err != nil {
        log.Fatalf("Auth error: %v", err)
    }
    defer a.Close()

    // 3. Register optional modules here (before Initialize)
    // By default, stateless JWT auth is used.

    // 4. Initialize
    if err := a.Initialize(context.Background()); err != nil {
        log.Fatalf("Initialize error: %v", err)
    }

    // 5. Register routes and serve
    mux := http.NewServeMux()
    stdhttp.Register(mux, a)

    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"message": "GoAuth is running!"}`))
    })

    log.Println("Server starting on :8080")
    log.Println("API at: http://localhost:8080/api/v1")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## 3. Run

```bash
go run main.go
```

## 4. Test the API

### Register

```bash
curl -X POST http://localhost:8080/api/v1/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

### Login

```bash
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

### Get Profile (Protected)

```bash
curl http://localhost:8080/api/v1/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## Three-Phase Pattern

```go
// 1. Create — Core module auto-registered
a, _ := auth.New(&config.Config{...})

// 2. Register optional modules
a.Use(notification.New(&notification.Config{...}))
a.Use(twofactor.New(&twofactor.TwoFactorConfig{...}))

// 3. Initialize — runs migrations, wires hooks, builds routes
a.Initialize(context.Background())

// Then register routes with a framework adapter
stdhttp.Register(mux, a)
```

## Adding Modules

### Session-based Auth

By default, GoAuth uses stateless JWT. To switch to server-side sessions:

```go
import "github.com/bete7512/goauth/internal/modules/session"

a.Use(session.New(&config.SessionModuleConfig{
    EnableSessionManagement: true,
    Strategy:                types.SessionStrategyCookieCache,
    SlidingExpiration:       true,
}, nil))
```

### Notifications

```go
import (
    "github.com/bete7512/goauth/internal/modules/notification"
    "github.com/bete7512/goauth/internal/modules/notification/services/senders"
)

a.Use(notification.New(&notification.Config{
    EmailSender: senders.NewSMTPEmailSender(&senders.SMTPConfig{
        Host:     "smtp.gmail.com",
        Port:     587,
        Username: "your-email@gmail.com",
        Password: "your-app-password",
    }),
    EnableWelcomeEmail:       true,
    EnablePasswordResetEmail: true,
}))
```

### Two-Factor Auth

```go
import "github.com/bete7512/goauth/internal/modules/twofactor"

a.Use(twofactor.New(&twofactor.TwoFactorConfig{
    Issuer:           "MyApp",
    Required:         false,
    BackupCodesCount: 10,
}))
```

## Framework Integration

GoAuth provides one-line adapters for popular frameworks:

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

## Production Tips

### Use PostgreSQL

```go
store, _ := storage.NewGormStorage(storage.GormConfig{
    Dialect:      types.DialectTypePostgres,
    DSN:          "host=localhost user=postgres password=secret dbname=authdb sslmode=disable",
    MaxOpenConns: 25,
    MaxIdleConns: 5,
})
```

### Use Environment Variables

```go
security := types.SecurityConfig{
    JwtSecretKey:  os.Getenv("JWT_SECRET_KEY"),
    EncryptionKey: os.Getenv("ENCRYPTION_KEY"),
    Session: types.SessionConfig{
        AccessTokenTTL:  15 * time.Minute,
        RefreshTokenTTL: 7 * 24 * time.Hour,
    },
}
```

### CORS

```go
a, _ := auth.New(&config.Config{
    // ...
    CORS: &config.CORSConfig{
        Enabled:        true,
        AllowedOrigins: []string{"http://localhost:3000"},
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
    },
})
```

## Next Steps

- [Core Module](/docs/modules/core) — Full Core module docs
- [Notification Module](/docs/modules/notification) — Email/SMS setup
- [API Reference](/docs/api/endpoints) — All endpoints
