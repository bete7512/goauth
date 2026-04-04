---
id: api-auth
title: Auth Lifecycle
sidebar_label: Auth
sidebar_position: 1
---

# Auth Lifecycle

GoAuth follows a three-phase lifecycle: **New → Use → Initialize**.

## Phase 1: Create

```go
import (
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/types"
    "github.com/bete7512/goauth/storage"
)

store := storage.NewGormStorage(storage.GormConfig{
    Dialect: types.DialectPostgres,
    DSN:     "host=localhost user=postgres password=secret dbname=myapp",
})

a, err := auth.New(&config.Config{
    Storage: store,
    Migration: config.MigrationConfig{Auto: true},
    Security: types.SecurityConfig{
        JwtSecretKey:  "your-secret-key-min-32-chars-long!",
        EncryptionKey: "your-encryption-key-32-chars!!",
    },
})
```

`auth.New()` validates the config, creates the event bus, middleware manager, security manager, and auto-registers the **Core module**.

## Phase 2: Register Modules

```go
import (
    "github.com/bete7512/goauth/pkg/modules/session"
    "github.com/bete7512/goauth/pkg/modules/admin"
)

a.Use(session.New(&config.SessionModuleConfig{}, nil))
a.Use(admin.New(nil))
```

Rules:
- `Use()` returns an error if called after `Initialize()`
- Session and Stateless modules are **mutually exclusive** — registering both causes a panic
- If neither Session nor Stateless is registered, **Stateless is used as default** with `RefreshTokenRotation: true`
- Core is auto-registered — never register it manually

## Phase 3: Initialize

```go
if err := a.Initialize(context.Background()); err != nil {
    log.Fatal(err)
}
defer a.Close()
```

`Initialize()`:
1. Auto-registers Stateless module if no auth module was registered
2. Runs database migrations (if `Migration.Auto` is true)
3. Initializes all modules (calls `Init()` on each)
4. Registers event hooks from all modules
5. Registers middleware from all modules
6. Starts the event bus (async backend begins consuming events)
7. Builds the route table

## Serving Routes

After initialization, register routes with your framework adapter:

```go
import "github.com/bete7512/goauth/pkg/adapters/stdhttp"

mux := http.NewServeMux()
stdhttp.Register(mux, a)
http.ListenAndServe(":8080", mux)
```

Available adapters: `stdhttp`, `ginadapter`, `chiadapter`, `fiberadapter`.

## Protecting Routes

Use `RequireAuth()` middleware on your own routes:

```go
mux.Handle("/api/protected", a.RequireAuth(http.HandlerFunc(myHandler)))
```

This validates the JWT access token and injects the user into the request context.

## Subscribing to Events

```go
a.On(types.EventAfterSignup, func(ctx context.Context, event *types.Event) error {
    // Handle new user signup
    return nil
})
```

Events must be subscribed **before** `Initialize()` is called (or within a module's `RegisterHooks` method).

## Authentication Header

Protected endpoints require:

```
Authorization: Bearer <access_token>
```

The access token is a HS256-signed JWT containing user ID, token version, and any enriched claims from interceptors (e.g., organization role).
