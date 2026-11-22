---
id: quickstart
title: Quick Start
seoTitle: "Go login and sign-up in 5 minutes: GoAuth Quick Start"
description: "Build a Go server with sign-up, login, JWT credentials and a protected route in about five minutes, using the GoAuth library and SQLite. No database to install."
keywords: ["golang login example", "go signup login tutorial", "golang jwt authentication example", "go protected route", "golang auth tutorial"]
sidebar_label: Quick Start
sidebar_position: 3
---

# Quick Start

In about five minutes you will have a Go server where people can sign up, log in, and call a route only signed-in users can reach. It uses SQLite, so there is no database to install.

## Before you start

- Go 1.26 or later.
- A C compiler, because the SQLite driver uses cgo.
- `openssl` to generate two secrets (any random strings of the right length work).

## 1. Create the project

```bash
mkdir hello-auth && cd hello-auth
go mod init hello-auth
go get github.com/bete7512/goauth@v0.3.0
```

## 2. Write main.go

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "os"

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
    // 1. Give GoAuth a database. SQLite keeps this guide free of setup.
    store, err := storage.NewGormStorage(storage.GormConfig{
        Dialect: types.DialectTypeSqlite,
        DSN:     "auth.db",
    })
    if err != nil {
        return err
    }

    // 2. Configure it.
    a, err := auth.New(&config.Config{
        Storage:   store,
        BasePath:  "/auth",
        Migration: config.MigrationConfig{Auto: true}, // create the tables at startup
        Core:      &config.CoreConfig{},               // required, even when empty
        Security: types.SecurityConfig{
            JwtSecretKey:  os.Getenv("JWT_SECRET_KEY"), // at least 32 bytes
            EncryptionKey: os.Getenv("ENCRYPTION_KEY"), // at least 16 bytes
            // Cookies are Secure by default. Allow plain HTTP on localhost only.
            Session: types.SessionConfig{AllowInsecureCookies: true},
        },
    })
    if err != nil {
        _ = store.Close() // New failed, so the store is still yours to close.
        return err
    }
    defer a.Close() // closes the store too

    // 3. Start it. Optional modules go in a.Use(...) calls before this line.
    if err := a.Initialize(context.Background()); err != nil {
        return err
    }

    // 4. Mount GoAuth's routes next to your own.
    mux := http.NewServeMux()
    mux.Handle("GET /private", a.RequireAuth(http.HandlerFunc(private)))

    log.Println("listening on http://localhost:8080")
    return http.ListenAndServe(":8080", stdhttp.Register(mux, a))
}

// private only runs for signed-in users.
func private(w http.ResponseWriter, r *http.Request) {
    user, _ := types.PrincipalFromContext(r.Context())
    fmt.Fprintf(w, "hello, %s\n", user.UserID)
}
```

The four numbered comments are the whole integration.

## 3. Run it

```bash
export JWT_SECRET_KEY="$(openssl rand -hex 32)"
export ENCRYPTION_KEY="$(openssl rand -hex 32)"
go mod tidy
go run .
```

Keep the two secrets the same between restarts. A new `JWT_SECRET_KEY` signs everyone out. If you forget to set them, the program stops with `jwt secret key must be at least 32 characters`.

## 4. Try it

Open a second terminal.

**Create an account**

```bash
curl -X POST http://localhost:8080/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com","password":"S3cure-pass!","first_name":"Ada","last_name":"Lovelace"}'
```

The answer is `201 Created`. Responses on this page are shortened to the interesting fields:

```json
{"data":{"user":{"id":"01a1e4aa-39f2-7013-a65a-74cd710bee94","first_name":"Ada","last_name":"Lovelace","email":"ada@example.com","username":"ada-01a1e4aa","active":true,"email_verified":false},"message":"Signup successful. Please login to continue."}}
```

**Log in**

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com","password":"S3cure-pass!"}'
```

```json
{"data":{"access_token":"eyJhbGciOi...","refresh_token":"eyJhbGciOi...","expires_in":900,"user":{"id":"01a1e4aa-39f2-7013-a65a-74cd710bee94","email":"ada@example.com"},"message":"Login successful"}}
```

Copy `data.access_token` and `data.refresh_token`. The access token lasts 15 minutes.

**Call your protected route**

```bash
curl http://localhost:8080/private -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

```text
hello, 01a1e4aa-39f2-7013-a65a-74cd710bee94
```

Without the token, the same request is refused:

```json
{"data":{"code":"UNAUTHORIZED","message":"invalid access credential"}}
```

**Read the profile**

```bash
curl http://localhost:8080/auth/me -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Get a new token pair**

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"YOUR_REFRESH_TOKEN"}'
```

Replace both saved tokens with the pair you get back. A refresh token works once: sending the old one again returns `INVALID_REFRESH_TOKEN`.

## What you have now

You registered no modules, so GoAuth used its defaults: [Core](modules/core.md) for accounts, [Stateless](modules/stateless.md) for JWT access and refresh tokens, and the [rate limiter](modules/ratelimit.md). Together they serve these endpoints under `/auth`:

| Endpoint | What it does |
| --- | --- |
| `POST /signup` | Create an account |
| `POST /login` · `POST /logout` · `POST /refresh` | Sign in, sign out, trade a refresh token for a new pair |
| `GET /me` · `PUT /profile` | Read and update the signed-in user |
| `PUT /change-password` | Change the password |
| `POST /forgot-password` · `POST /reset-password` | Recover a forgotten password |
| `POST /send-verification-email` · `GET /verify-email` | Verify an email address |
| `POST /send-verification-phone` · `POST /verify-phone` | Verify a phone number |
| `POST /is-available` | Check whether an email, username or phone is taken |

Password-reset and verification messages are not sent yet. Add the [Notification module](modules/notification.md) to send them. The [API reference](api/endpoints.md) documents every request and response.

## Add your first module

A module is one `a.Use(...)` call, placed before `a.Initialize`. `Use` returns an error when a module is registered twice, conflicts with another, or is added too late, so always check it.

For example, authenticator-app two-factor, from `pkg/modules/twofactor`:

```go
if err := a.Use(twofactor.New(&config.TwoFactorConfig{
    Issuer: "MyApp",
})); err != nil {
    return err
}
```

Once it is on, a correct password may answer with a `challenges` list instead of tokens, and your client has to finish the challenge first. The [Introduction](intro.md#one-sign-in-path) shows the response.

The [Examples](showcase.md) page has setups for sessions, email, social login, passkeys, organizations and the admin console.

## Use your own router

`stdhttp.Register` is for `net/http`. Gin, Chi and Fiber have adapters that replace that one line; see [Installation](installation.md#framework-adapters).

## Before real users sign in

The program above is fine for a laptop. For production, change four things:

1. **Use PostgreSQL or MySQL.** Only the storage block changes; see [Installation](installation.md#connect-a-database).
2. **Remove `AllowInsecureCookies`** and serve over HTTPS.
3. **Keep the secrets in a secret store**, and keep them stable across deploys.
4. **Stop cleanly.** Stop the HTTP server first, then GoAuth. Replace the last two lines of `run` with:

```go
server := &http.Server{
    Addr:              ":8080",
    Handler:           stdhttp.Register(mux, a),
    ReadHeaderTimeout: 5 * time.Second,
}
stop, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer cancel()

serverErr := make(chan error, 1)
go func() { serverErr <- server.ListenAndServe() }()

select {
case err := <-serverErr:
    return err
case <-stop.Done():
}

ctx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
defer cancelShutdown()
return server.Shutdown(ctx) // the deferred a.Close() then stops GoAuth
```

It needs the `os/signal`, `syscall` and `time` imports. The [Production checklist](production.md) has the full list.

## Next

- [Introduction](intro.md): how the pieces fit together.
- [Examples](showcase.md): working setups for common features.
- [Security](security.md): cookies, tokens and keys.
- [API reference](api/endpoints.md): every endpoint.
