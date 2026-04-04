---
id: stateless
title: Stateless Module
sidebar_label: Stateless
sidebar_position: 4
---

# Stateless Module

JWT-based stateless authentication with zero per-request database queries. This is the **default** auth module — if no auth module is explicitly registered, Stateless is auto-registered with `RefreshTokenRotation: true`. Mutually exclusive with [Session](session.md).

The Stateless module issues short-lived JWT access tokens and long-lived refresh tokens. Access tokens are validated purely from their cryptographic signature and expiry — no database lookup is needed on every request. Refresh tokens use a JTI (JWT ID) nonce mechanism to prevent replay attacks: each refresh token can only be used once, and using it atomically rotates the nonce.

## Capabilities

- **JWT Access + Refresh Tokens** — Short-lived access tokens (default: 15 minutes) for API authorization, long-lived refresh tokens (default: 7 days) for obtaining new access tokens.
- **Zero Per-Request DB Queries** — Access token validation uses only the JWT signature and expiry claims. No database round-trip is needed, making this ideal for high-throughput APIs.
- **Refresh Token Rotation** — Each refresh token contains a unique JTI (JWT ID). On refresh, the old JTI is atomically deleted and a new one is issued, ensuring single-use refresh tokens.
- **Replay Attack Prevention** — If a stolen refresh token is replayed after the legitimate user has already refreshed, the JTI will not be found in the database and the request is rejected.
- **Token Version Revocation** — The user's `TokenVersion` field is embedded in JWTs. Incrementing it (e.g., on password change) instantly invalidates all existing tokens for that user.
- **Custom Token Storage** — Pass your own `types.CoreStorage` implementation to control where refresh token nonces are stored.

## Registration

```go
import (
    "github.com/bete7512/goauth/pkg/modules/stateless"
    "github.com/bete7512/goauth/pkg/config"
)

a.Use(stateless.New(&config.StatelessModuleConfig{
    RefreshTokenRotation: true,
}, nil))
```

Or just don't register any auth module — Stateless is auto-registered with `RefreshTokenRotation: true`.

The second argument is an optional custom `types.CoreStorage`. If `nil`, the module uses `deps.Storage.Core()` from Initialize. The Stateless module uses `CoreStorage` because it only needs the Users and Tokens repositories.

## Configuration

```go
type StatelessModuleConfig struct {
    // Rotate refresh tokens on each refresh (default: true when auto-registered)
    RefreshTokenRotation bool
}
```

Token TTLs are set in `SecurityConfig.Session`:

```go
Security: types.SecurityConfig{
    Session: types.SessionConfig{
        AccessTokenTTL:  15 * time.Minute,  // Default: 15 minutes
        RefreshTokenTTL: 7 * 24 * time.Hour, // Default: 7 days
    },
}
```

## Endpoints

All paths are prefixed with your `BasePath` (default: `/auth`).

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/login` | No | Authenticate, returns JWT access + refresh tokens |
| POST | `/logout` | Yes | Revoke the current refresh token nonce |
| POST | `/refresh` | No | Get new access token (rotates refresh token if enabled) |

## Refresh Token Rotation (JTI/Nonce Mechanism)

When `RefreshTokenRotation` is enabled, the module uses a JTI (JWT ID) nonce stored in the database to ensure each refresh token can only be used once.

### How it works

1. **Login**: The server generates a refresh token JWT containing a unique `jti` claim. The JTI value is stored in the `tokens` table as a `refresh_nonce` record.

2. **Refresh**: When the client sends the refresh token:
   - The JWT signature and expiry are validated.
   - The `jti` claim is extracted and looked up in the database.
   - If the JTI is found, the old nonce record is **deleted** (revoked).
   - A new access token and a new refresh token (with a new JTI) are generated.
   - The new JTI is saved to the database.

3. **Replay detection**: If a previously-used refresh token is replayed, its JTI will not be found in the database (it was deleted during the legitimate refresh), so the request is rejected.

This gives single-use refresh tokens without maintaining a blacklist. The `tokens` table only stores active nonces, and each refresh atomically rotates the nonce.

### Token storage

The module uses `CoreStorage.Tokens()` (the `TokenRepository`) for nonce records. Each record has:
- `type`: `"refresh_nonce"`
- `token`: the JTI value (not the full JWT)
- `expires_at`: matches the refresh token TTL

## Dependencies

The Stateless module depends on the **Core** module (auto-registered). It uses `CoreStorage` for both user lookups and refresh token nonce tracking.

## Extensibility

### Custom Token Storage

The second argument to `stateless.New()` accepts a custom `types.CoreStorage` implementation. If `nil`, the module uses `deps.Storage.Core()` from the shared storage layer.

```go
// Use your own storage backend
a.Use(stateless.New(statelessConfig, myCustomCoreStorage))

// Or use the built-in GORM-backed storage
a.Use(stateless.New(statelessConfig, nil))
```

The Stateless module uses `CoreStorage.Tokens()` (the `TokenRepository`) for refresh token nonce records and `CoreStorage.Users()` for user lookups during login.

### Event Hooks

The Stateless module emits login/logout events that other modules and custom handlers can subscribe to:

| Before | After |
|--------|-------|
| `EventBeforeLogin` | `EventAfterLogin` |
| `EventBeforeLogout` | `EventAfterLogout` |

Additional events: `EventAfterPasswordVerified`, `EventAuthLoginSuccess`, `EventAuthLoginFailed`.

## Next Steps

- [Core Module](core.md) — User management, signup, verification
- [Session Module](session.md) — Alternative server-side session auth
- [API Reference](/docs/api/endpoints) — All endpoints
