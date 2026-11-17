---
slug: jwt-refresh-token-rotation-go
title: JWT Access and Refresh Token Rotation in Go
description: JWT refresh token rotation in Go with GoAuth. Issue short-lived access tokens, make refresh tokens single-use, and choose stateless or session mode.
keywords: ["jwt refresh token rotation go", "golang jwt refresh token", "go jwt authentication", "refresh token rotation", "golang access token refresh", "stateless jwt go"]
authors: [goauth-team]
tags: [jwt, go, authentication, security, tutorial]
---

# JWT Access and Refresh Token Rotation in Go

Short-lived JWT access tokens are easy to verify, but users should not sign in every 15 minutes. The usual answer is a refresh token that is rotated on every use. This post shows how JWT access and refresh token rotation works in a Go (Golang) server with GoAuth's stateless module, and when to choose the session module instead.

<!-- truncate -->

## What you will build

A Go API where:

- `POST /auth/login` returns an access token (15 minutes) and a refresh token (7 days).
- `POST /auth/refresh` trades a refresh token for a new pair and invalidates the old refresh token.
- `GET /api/me` is a route of your own that only accepts a valid access token.

## Prerequisites

- Go 1.26 or later, and a C compiler for the SQLite driver.
- The program from the [Quick Start](/docs/quickstart). Stateless is already the default strategy there; this post makes it explicit and explains what it does.

## Step 1: Configure token lifetimes

Lifetimes live under `Security.Session`. These values are the defaults, written out so you can see them:

```go
a, err := auth.New(&config.Config{
    Storage:   store,
    BasePath:  "/auth",
    Migration: config.MigrationConfig{Auto: true},
    Core:      &config.CoreConfig{},
    Security: types.SecurityConfig{
        JwtSecretKey:  os.Getenv("JWT_SECRET_KEY"), // at least 32 bytes
        EncryptionKey: os.Getenv("ENCRYPTION_KEY"),
        AuthMode:      types.AuthModeBearer, // tokens in JSON, no cookies
        Session: types.SessionConfig{
            AccessTokenTTL:  15 * time.Minute,
            RefreshTokenTTL: 7 * 24 * time.Hour,
        },
    },
})
```

`AuthModeBearer` keeps this example to JSON and `Authorization` headers. The default, `AuthModeBoth`, also sets HTTP-only cookies, which is the better choice for browser apps.

## Step 2: Register the stateless module

```go
import "github.com/bete7512/goauth/pkg/modules/stateless"

if err := a.Use(stateless.New(nil)); err != nil {
    return err
}
if err := a.Initialize(context.Background()); err != nil {
    return err
}
```

`stateless.New(nil)` uses safe defaults. If you register neither Stateless nor Session, GoAuth registers Stateless for you. Registering both returns an error from `Use`.

Then protect your own route:

```go
mux := http.NewServeMux()
mux.Handle("GET /api/me", a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    p, _ := types.PrincipalFromContext(r.Context())
    fmt.Fprintln(w, p.UserID)
})))
return http.ListenAndServe(":8080", stdhttp.Register(mux, a))
```

## Step 3: Log in, call, refresh

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com","password":"S3cure-pass!"}'
```

```json
{"data":{"access_token":"eyJhbGciOi...","refresh_token":"eyJhbGciOi...","expires_in":900}}
```

Call your route with the access token:

```bash
curl http://localhost:8080/api/me -H "Authorization: Bearer ACCESS_TOKEN"
```

When it expires, refresh:

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"REFRESH_TOKEN"}'
```

You get a new access token and a new refresh token. Replace both. Sending the old refresh token again fails with `INVALID_REFRESH_TOKEN`.

A refresh can also answer with a `challenges` list instead of tokens, when current policy asks for another factor. Keep the old pair in that case; do not overwrite it with empty values.

## How rotation works

Both tokens are signed JWTs, but the refresh token is only half of the story. The other half is a database record.

1. At login GoAuth issues a refresh JWT with `type: refresh`, the user ID, the user's `token_version` and a random `jti`.
2. The `jti` is stored as a `refresh_nonce` record in the `tokens` table, together with the grant context: how the user signed in, when, and the selected organization.
3. On refresh, GoAuth checks the signature, then the live record: it must exist, belong to the user, be unused and unexpired. It also checks that the user is still allowed to sign in and that `token_version` matches.
4. Interceptors run again with the stored grant context, so a policy such as two-factor still applies.
5. The old record is consumed and the new one is created in one atomic operation. If two requests race with the same refresh token, only one wins.

The new record keeps the **original** expiry. Refreshing every day does not stretch a 7-day login into forever: after 7 days from sign-in, the user signs in again.

Access validation is not signature-only either. Each protected request loads the user and checks token version, active status, required verification and organization membership. That is what makes logout and bans take effect before the access token expires.

## Stateless vs session

Both modules rotate refresh credentials once per use and keep the original expiry. They differ in what is stored and what logout means.

| | Stateless | Session |
| --- | --- | --- |
| Refresh credential | Signed JWT plus a stored nonce | Opaque secret, stored as a hash |
| Server record | One nonce per refresh token | One session per sign-in, with request metadata |
| Logout | Every device: bumps the token version and deletes all the user's nonces | Only the current session |
| Device list | No | `GET /sessions`, revoke one or all |

Choose **stateless** for APIs and mobile clients where "sign out everywhere" is acceptable. Choose **session** when users need to see and revoke individual devices:

```go
import "github.com/bete7512/goauth/pkg/modules/session"

if err := a.Use(session.New(nil)); err != nil {
    return err
}
```

The login and refresh routes stay the same, so clients do not change.

## Security notes

- **Refresh tokens are single-use.** A consumed nonce can never renew credentials again. GoAuth refuses the reused token; it does not also revoke the newer one, so treat repeated `INVALID_REFRESH_TOKEN` errors as a signal worth logging.
- **The `RefreshTokenRotation` field does not turn rotation off.** It is kept for compatibility; the current service always rotates.
- **Store refresh tokens carefully.** In browsers, prefer the HTTP-only cookies of `AuthModeBoth` or `AuthModeCookie`, with the CSRF module, over `localStorage`.
- **Downstream services.** A service that only checks the JWT signature cannot see logouts or bans. Route checks through GoAuth or call `a.Authenticate`.
- **Keys.** HS256 is the default. RS256 and ES256 are supported, with retained keys for rotation; see the [Security guide](/docs/security).

## Next steps

- [Stateless module reference](/docs/modules/stateless)
- [Session module reference](/docs/modules/session)
- [Two-Factor module](/docs/modules/twofactor)
- [Production checklist](/docs/production)
