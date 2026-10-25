---
id: quickstart
title: Quick Start
sidebar_label: Quick Start
sidebar_position: 3
---

# Quick Start

Run a GoAuth HTTP server with SQLite, password sign-in, and stateless JWT credentials. This guide targets the current repository API; see [Upgrading](upgrade.md) when moving from older constructor signatures.

## Prerequisites

- Go 1.25 or later and a C compiler for the SQLite driver.
- A Go module and two application secrets, loaded from the environment.

## 1. Project Setup

```bash
mkdir goauth-demo
cd goauth-demo
go mod init goauth-demo
go get github.com/bete7512/goauth@v0.3.0-beta.1
```

When testing an unreleased checkout, point the module at that checkout with `go mod edit -replace github.com/bete7512/goauth=/absolute/path/to/go-auth`. Published versions may not contain the APIs described here yet.

## 2. Create main.go

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/bete7512/goauth/pkg/adapters/stdhttp"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/types"
    "github.com/bete7512/goauth/storage"
)

func main() {
    if err := run(); err != nil {
        log.Fatal(err)
    }
}

func run() error {
    store, err := storage.NewGormStorage(storage.GormConfig{
        Dialect: types.DialectTypeSqlite,
        DSN:     "auth.db",
    })
    if err != nil {
        return err
    }

    a, err := auth.New(&config.Config{
        Storage:   store,
        Migration: config.MigrationConfig{Auto: true},
        BasePath:  "/api/v1",
        Security: types.SecurityConfig{
            JwtSecretKey:  os.Getenv("JWT_SECRET_KEY"),
            EncryptionKey: os.Getenv("ENCRYPTION_KEY"),
            JWTIssuer:    "goauth-demo",
            JWTAudience:  "goauth-demo-api",
            AuthMode:     types.AuthModeBearer,
            Lockout: types.LockoutConfig{Enabled: true},
            Session: types.SessionConfig{
                AccessTokenTTL:  15 * time.Minute,
                RefreshTokenTTL: 7 * 24 * time.Hour,
            },
        },
        Core: &config.CoreConfig{
            RequireEmailVerification: false, // Local demo has no mail sender.
        },
    })
    if err != nil {
        _ = store.Close()
        return err
    }
    defer a.Close() // Auth owns storage unless BorrowStorage is true.

    // Register optional modules here and check each a.Use(...) error.
    // With no explicit strategy, Initialize selects stateless JWT.
    if err := a.Initialize(context.Background()); err != nil {
        return err
    }

    mux := http.NewServeMux()
    stdhttp.Register(mux, a)
    mux.Handle("GET /private", a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        principal, ok := types.PrincipalFromContext(r.Context())
        if !ok {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        fmt.Fprintf(w, "Hello %s", principal.UserID)
    })))

    server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
    stopped, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer cancel()
    serverErrors := make(chan error, 1)
    go func() { serverErrors <- server.ListenAndServe() }()
    log.Println("GoAuth API: http://localhost:8080/api/v1")

    select {
    case err := <-serverErrors:
        if !errors.Is(err, http.ErrServerClosed) {
            return err
        }
    case <-stopped.Done():
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        if err := server.Shutdown(ctx); err != nil {
            return err
        }
    }
    return nil
}
```

## 3. Run

Generate separate secrets for local development and retain them across restarts. The following commands require OpenSSL:

```bash
export JWT_SECRET_KEY="$(openssl rand -hex 32)"
export ENCRYPTION_KEY="$(openssl rand -hex 32)"
go mod tidy
go run .
```

`JwtSecretKey` must be at least 32 bytes and `EncryptionKey` at least 16 bytes. Do not regenerate production secrets on every start; see [Signing and rotation](security.md).

## 4. Test the API

### Register

```bash
curl -X POST http://localhost:8080/api/v1/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePassword123!","first_name":"John","last_name":"Doe"}'
```

### Login

```bash
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePassword123!"}'
```

Read `data.access_token` and `data.refresh_token` from the JSON response. If you later enable two-factor authentication, handle `data.challenges` before treating a response as authenticated.

### Get Profile (Protected)

```bash
curl http://localhost:8080/api/v1/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Refresh

```bash
curl -X POST http://localhost:8080/api/v1/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"YOUR_REFRESH_TOKEN"}'
```

Replace both saved credentials with the returned pair. A consumed refresh credential cannot be reused.

## Three-Phase Pattern

Create the instance, register modules, and initialize exactly once. `Use` returns errors for duplicate modules, invalid modules, conflicting strategies, and registration after initialization. Do not discard those errors.

```go
if err := a.Use(twofactor.New()); err != nil {
    return err
}
if err := a.Initialize(ctx); err != nil {
    return err
}
```

This is a fragment inside your setup function; add the `pkg/modules/twofactor` import.

## Adding Modules

Register these before `Initialize`.

### Session-based Auth

```go
if err := a.Use(session.New(&config.SessionModuleConfig{
    EnableSessionManagement: true,
})); err != nil {
    return err
}
```

Import `pkg/modules/session`. Sessions and Stateless cannot be registered together. Session records are checked during protected requests; changing the strategy does not select cookie versus bearer transport.

### Notifications

```go
if err := a.Use(notification.New(&notification.Config{
    EmailSender: senders.NewSMTPEmailSender(&senders.SMTPConfig{
        Host:     os.Getenv("SMTP_HOST"),
        Port:     587,
        Username: os.Getenv("SMTP_USERNAME"),
        Password: os.Getenv("SMTP_PASSWORD"),
    }),
    EnableWelcomeEmail: true,
})); err != nil {
    return err
}
```

Import `pkg/modules/notification` and `pkg/modules/notification/senders`. Configure sender addresses and frontend callback paths as described in the [notification guide](modules/notification.md) before enabling required verification.

### Two-Factor Auth

```go
if err := a.Use(twofactor.New(&config.TwoFactorConfig{
    Issuer: "MyApp",
    BackupCodesCount: 10,
})); err != nil {
    return err
}
```

`twofactor.New()` also accepts no arguments. The [2FA guide](modules/twofactor.md) documents the continuation response and verification request.

### Passkeys

```go
if err := a.Use(passkeys.New(&config.PasskeysModuleConfig{
    RPDisplayName: "MyApp",
    RPID: "localhost",
    RPOrigins: []string{"http://localhost:3000"},
})); err != nil {
    return err
}
```

Import `pkg/modules/passkeys`. The RP origin identifies the frontend performing the WebAuthn ceremony. See [Passkeys](modules/passkeys.md) for begin/finish payloads and storage requirements.

## Framework Integration

The standard HTTP adapter is in the root module. Gin, Chi, and Fiber adapters are separate Go modules:

```bash
go get github.com/bete7512/goauth/pkg/adapters/ginadapter@v0.3.0-beta.1
go get github.com/bete7512/goauth/pkg/adapters/chiadapter@v0.3.0-beta.1
go get github.com/bete7512/goauth/pkg/adapters/fiberadapter@v0.3.0-beta.1
```

After initialization, use `ginadapter.Register(router, a)`, `chiadapter.Register(router, a)`, or `fiberadapter.Register(app, a)`. See the [framework guide](frameworks/gin.md).

## Production Tips

Use a persistent database, stable secrets, explicit issuer and audience, and leave `Security.Session.AllowInsecureCookies` unset so cookies keep the Secure attribute. Cookie clients also need CSRF protection. Set CORS in your own HTTP/framework middleware; GoAuth has no CORS config field.

Plan migrations with [Migration management](migrations.md). If the application owns an existing storage connection, set `BorrowStorage: true` and close it after GoAuth shuts down. Both JWT and session strategies require shared persistent state across replicas.

## Next Steps

- [Authentication lifecycle and in-process API](api/auth.md)
- [Security and credentials](security.md)
- [API Endpoints](api/endpoints.md)
