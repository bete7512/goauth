---
id: session
title: Session Module
sidebar_label: Session
sidebar_position: 3
---

# Session Module

The Session module issues access JWTs backed by a live session record and an opaque refresh credential stored as a hash. It is mutually exclusive with [Stateless](stateless.md); trying to register both returns an error.

## Registration

```go
if err := a.Use(session.New(&config.SessionModuleConfig{
    EnableSessionManagement: true,
    Strategy: types.SessionStrategyCookieCache,
    CookieEncoding: types.CookieEncodingCompact,
    CookieCacheTTL: 5 * time.Minute,
    UpdateAge: 10 * time.Minute,
    SensitivePaths: []string{"/api/v1/admin/*"},
})); err != nil {
    return err
}
```

Import `pkg/modules/session`, `pkg/config`, `pkg/types`, and `time`. Pass one config argument; `session.New(nil)` uses defaults. Custom storage belongs in `SessionModuleConfig.CustomStorage`, not a second constructor argument.

## Capabilities

- Each completed authentication creates a session containing user, expiry, request metadata when available, a hashed refresh secret, and persisted grant context.
- Access validation checks the current user and **live session on every protected request**, including when cookie caching is configured.
- Refresh atomically replaces the refresh secret while retaining the logical session ID and absolute expiry. Concurrent reuse fails.
- Revoking a session makes its access credentials fail the next online validation.
- Session management lists, reads, and deletes the authenticated user's sessions.
- The same strategy is used by password, OAuth, magic link, passkey, invitation, and resumed 2FA authentication through the shared completion service.

## Configuration

| Field | Effective behavior |
| --- | --- |
| `CustomStorage` | Optional `types.SessionStorage`; resolved as the shared session store before modules initialize |
| `EnableSessionManagement` | Retained config field; current handlers register the management routes regardless of this value |
| `Strategy` | Empty/`database` uses normal access validation; `cookie_cache` adds cache-cookie handling |
| `CookieEncoding` | Empty/`compact` or `jwt`; applies to the additional session-cache cookie |
| `CookieCacheTTL` | Cache cookie lifetime, default 5 minutes |
| `UpdateAge` | Forces a cache revalidation after this age, default 10 minutes |
| `SensitivePaths` | Exact paths or trailing `/*` patterns that force cache revalidation |
| `SlidingExpiration` | Optional cache-validator extension, capped at `CreatedAt + SessionTTL` |

Set access, refresh, and absolute session lifetimes under `Security.Session`. Defaults are 15 minutes, 7 days, and 30 days respectively. Refreshed credentials cannot extend the stored absolute session expiry.

### Strategy: `database` (Default)

The common access boundary checks signature, issuer, audience, credential purpose, subject, token version, and current account eligibility. It then loads the session, checks ownership and expiry, and validates selected-organization membership when present. The strategy is not signature-only validation.

### Strategy: `cookie_cache`

A signed `goauth_session_{Session.Name}` cookie carries session-cache data. The cache middleware can reissue this cookie after expiry, `UpdateAge`, or a sensitive-path match. A cookie with a different session/user identity is rejected.

This additional cache **does not bypass** the common online user/session checks. It is disabled in bearer-only mode. `SlidingExpiration` is bounded by the original session's absolute lifetime; do not rely on it for indefinite sessions. `RequireAuth` on a host route performs common access validation but does not install every module's cache middleware.

## Endpoints

Prefix every path with `BasePath` (default `/auth`).

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| POST | `/login` | Public | Verify password, then complete auth or return challenges |
| POST | `/logout` | Access | Delete current session and clear credential cookies |
| POST | `/refresh` | Refresh credential | Rotate refresh secret and return new credentials |
| GET | `/sessions` | Access | List the user's sessions |
| GET | `/sessions/{session_id}` | Access | Read an owned session |
| DELETE | `/sessions/{session_id}` | Access | Revoke an owned session |
| DELETE | `/sessions` | Access | Revoke **all** of the user's sessions, including the current one |

Management routes are currently present whenever Session is registered; `EnableSessionManagement: false` is not an access-control boundary. Session responses use DTOs so stored refresh hashes and `AuthData` are not exposed.

## Refresh and Transport

Refresh accepts the configured cookie or bearer inputs, applying the [shared transport policy](../security.md#credential-transport). In bearer mode, send JSON `refresh_token` or the refresh credential as a Bearer header. In cookie-only mode, send the refresh cookie. Conflicting enabled credentials are rejected.

A refresh can return `challenges` if current policy requires another factor. Do not overwrite a valid credential pair with empty values from a challenge response.

## Custom Session Storage

```go
if err := a.Use(session.New(&config.SessionModuleConfig{
    CustomStorage: mySessionStore,
})); err != nil {
    return err
}
```

The repository must implement `models.SessionRotator` for atomic refresh. Authentication completion involving transactions also needs the same session store available inside the aggregate `types.TransactionalStorage` callback. Independent custom stores cannot satisfy that guarantee merely by implementing a transaction on each store. See [Custom storage](../storage.md).

## Event Hooks

Password authentication and logout have before/after hooks. Other authenticators retain their own events; do not assume every sign-in method emits every password-login event. See [Events](../enterprise.md).

## Dependencies

Core and Session storage are required. Core is auto-registered. See [Stateless](stateless.md) for the alternative credential strategy and [Security](../security.md) for JWT signing.
