---
id: session
title: Session Module
sidebar_label: Session
sidebar_position: 3
---

# Session Module

Server-side session authentication. Mutually exclusive with [Stateless](stateless.md) — registering both panics. If neither is registered, Stateless is used as the default.

## Features

- Server-side sessions stored in database
- Cookie-based session validation strategies
- Session management (list, get, revoke)
- Sliding expiration for active users
- Sensitive path enforcement (always validates against DB)

## Registration

```go
import "github.com/bete7512/goauth/internal/modules/session"

a.Use(session.New(&config.SessionModuleConfig{
    EnableSessionManagement: true,
    Strategy:                types.SessionStrategyCookieCache,
    CookieCacheTTL:          5 * time.Minute,
    SlidingExpiration:       true,
    UpdateAge:               10 * time.Minute,
    SensitivePaths:          []string{"/admin/*"},
}, nil))
```

## Configuration

```go
type SessionModuleConfig struct {
    // Enable session list/delete endpoints
    EnableSessionManagement bool

    // Validation strategy:
    //   "database" (default) — JWT-only, DB used for refresh/logout
    //   "cookie_cache" — Signed session cookie, avoids DB per-request
    Strategy types.SessionStrategy

    // Cookie encoding: "compact" (default, ~200 bytes) or "jwt" (~400 bytes)
    CookieEncoding types.CookieEncoding

    // How long the cookie is trusted before DB re-validation (default: 5min)
    CookieCacheTTL time.Duration

    // Paths that always validate against DB even with valid cookie cache
    SensitivePaths []string

    // Extend session on activity (default: false)
    SlidingExpiration bool

    // Force DB re-validation after this duration (default: 10min)
    UpdateAge time.Duration
}
```

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/login` | — | Authenticate and create session |
| POST | `/logout` | ✓ | End session |
| POST | `/refresh` | — | Refresh tokens |
| GET | `/sessions` | ✓ | List active sessions |
| GET | `/sessions/{id}` | ✓ | Get session details |
| DELETE | `/sessions/{id}` | ✓ | Revoke specific session |
| DELETE | `/sessions` | ✓ | Revoke all except current |

Session management endpoints require `EnableSessionManagement: true`.
