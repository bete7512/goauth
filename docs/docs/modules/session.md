---
id: session
title: Session Module
sidebar_label: Session
sidebar_position: 3
---

# Session Module

Server-side session authentication with full session lifecycle management. Mutually exclusive with [Stateless](stateless.md) — registering both panics. If neither is registered, Stateless is used as the default.

The Session module stores session records in the database and provides two validation strategies: a simple database-backed approach and an optimized cookie-cache strategy that eliminates per-request database queries for most requests. It gives you complete visibility into active sessions, the ability to revoke individual or all sessions, and sliding expiration to keep active users logged in.

## Capabilities

- **Server-Side Sessions** — Each login creates a session record in the database with metadata (IP address, user agent, device info). Sessions are first-class entities you can query, list, and manage.
- **Two Validation Strategies** — Choose `database` (simple, always-consistent) or `cookie_cache` (high-performance, eventually-consistent within the cache TTL window).
- **Cookie-Cache Strategy** — Signed session cookies avoid DB round-trips on every request. The cookie encodes session validity and is trusted for `CookieCacheTTL` (default: 5 minutes). Two encoding formats: `compact` (~200 bytes) or `jwt` (~400 bytes).
- **Sliding Expiration** — Automatically extends session lifetime when users are active. The extension window is `UpdateAge / 2` before expiry, preventing premature session death for active users.
- **Sensitive Path Bypass** — Define path patterns (e.g., `/admin/*`) that always validate against the database, even with a valid cookie cache. Ensures revoked sessions cannot access critical routes within the cache window.
- **Session Management Endpoints** — List all active sessions, inspect individual sessions, revoke a specific session, or revoke all sessions except the current one. Useful for "sign out everywhere" functionality.
- **Custom Session Storage** — Pass your own `types.SessionStorage` implementation to the constructor for custom backends (Redis, Memcached, etc.).

## Registration

```go
import (
    "github.com/bete7512/goauth/pkg/modules/session"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/types"
)

a.Use(session.New(&config.SessionModuleConfig{
    EnableSessionManagement: true,
    Strategy:                types.SessionStrategyCookieCache,
    CookieEncoding:          types.CookieEncodingCompact,
    CookieCacheTTL:          5 * time.Minute,
    SlidingExpiration:       true,
    UpdateAge:               10 * time.Minute,
    SensitivePaths:          []string{"/admin/*"},
}, nil))
```

The second argument is an optional custom `types.SessionStorage`. If `nil`, the module uses `deps.Storage.Session()` from Initialize.

## Configuration

```go
type SessionModuleConfig struct {
    // Enable session list/delete endpoints
    EnableSessionManagement bool

    // Validation strategy:
    //   "database" (default) — JWT-only validation, DB used for refresh/logout
    //   "cookie_cache" — Signed session cookie, avoids DB per-request
    Strategy types.SessionStrategy

    // Cookie encoding: "compact" (default, ~200 bytes) or "jwt" (~400 bytes)
    CookieEncoding types.CookieEncoding

    // How long the cookie is trusted before DB re-validation (default: 5min)
    CookieCacheTTL time.Duration

    // Paths that always validate against DB even with valid cookie cache.
    // Supports wildcard patterns (e.g., "/admin/*").
    SensitivePaths []string

    // Extend session on activity (default: false)
    SlidingExpiration bool

    // Force DB re-validation after this duration (default: 10min).
    // Also defines the extension window threshold for sliding expiration
    // (window = UpdateAge/2).
    UpdateAge time.Duration
}
```

### Config Fields Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `EnableSessionManagement` | `bool` | `false` | Enables session list/get/delete endpoints |
| `Strategy` | `types.SessionStrategy` | `"database"` | Validation strategy per request |
| `CookieEncoding` | `types.CookieEncoding` | `"compact"` | Cookie format: `"compact"` (~200 bytes) or `"jwt"` (~400 bytes) |
| `CookieCacheTTL` | `time.Duration` | `5m` | How long the cookie is trusted without DB check |
| `SensitivePaths` | `[]string` | `nil` | Path patterns that always check DB |
| `SlidingExpiration` | `bool` | `false` | Extend session expiry on activity |
| `UpdateAge` | `time.Duration` | `10m` | Force DB re-check after this duration |

### Strategy: `database` (Default)

The simplest strategy. The JWT access token is validated using its signature and expiry only. The session database is hit only during login, refresh, and logout. There are no per-request revocation checks, so revoking a session takes effect only when the access token expires.

### Strategy: `cookie_cache`

On login, the server issues a signed session cookie alongside the JWT access token. On each request, the middleware checks the cookie:

1. If the cookie is valid and younger than `CookieCacheTTL`, the request proceeds without a DB query.
2. If the cookie is stale (older than `CookieCacheTTL`) or the path matches `SensitivePaths`, the middleware re-validates against the database and issues a fresh cookie.
3. If `SlidingExpiration` is enabled and the session is within the extension window (`UpdateAge / 2` before expiry), the session's `ExpiresAt` is extended in the DB.

This gives near-zero-latency validation for most requests while still supporting session revocation within the `CookieCacheTTL` window.

## Endpoints

All paths are prefixed with your `BasePath` (default: `/auth`).

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/login` | No | Authenticate and create session |
| POST | `/logout` | Yes | End current session |
| POST | `/refresh` | No | Refresh tokens |
| GET | `/sessions` | Yes | List active sessions |
| GET | `/sessions/{session_id}` | Yes | Get session details |
| DELETE | `/sessions/{session_id}` | Yes | Revoke specific session |
| DELETE | `/sessions` | Yes | Revoke all sessions except current |

Session management endpoints (`/sessions/*`) require `EnableSessionManagement: true`.

## Dependencies

The Session module depends on the **Core** module (auto-registered). It requires both `SessionStorage` (for session records) and `CoreStorage` (for user lookups).

## Extensibility

### Custom Session Storage

The second argument to `session.New()` accepts a custom `types.SessionStorage` implementation. If `nil`, the module uses `deps.Storage.Session()` from the shared storage layer.

```go
// Use your own session store (e.g., Redis-backed)
a.Use(session.New(sessionConfig, myRedisSessionStorage))

// Or use the built-in GORM-backed storage
a.Use(session.New(sessionConfig, nil))
```

Implement `types.SessionStorage` to store sessions in Redis, DynamoDB, or any other backend. The interface requires methods for creating, reading, updating, and deleting session records.

### Event Hooks

The Session module emits login/logout events that other modules and custom handlers can subscribe to:

| Before | After |
|--------|-------|
| `EventBeforeLogin` | `EventAfterLogin` |
| `EventBeforeLogout` | `EventAfterLogout` |

Use `a.On(types.EventAfterLogin, handler)` to trigger custom logic after each login (e.g., update analytics, sync to CRM, send login alerts).

## Next Steps

- [Core Module](core.md) — User management, signup, verification
- [Stateless Module](stateless.md) — Alternative JWT-only auth
- [API Reference](/docs/api/endpoints) — All endpoints
