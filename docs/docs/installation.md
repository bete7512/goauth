---
id: installation
title: Installation
sidebar_label: Installation
sidebar_position: 2
description: Install GoAuth, connect PostgreSQL, MySQL or SQLite, and add a framework adapter.
---

# Installation

## What you need

- **Go 1.26 or later.**
- **A database.** PostgreSQL, MySQL or SQLite. Use SQLite for development and tests, and PostgreSQL or MySQL in production.
- **A C compiler, only for SQLite.** The SQLite driver uses cgo. PostgreSQL and MySQL do not need one.

## Install

```bash
go get github.com/bete7512/goauth@v0.3.0-beta.1
```

Name the version. A plain `go get` picks the newest non-beta release, and every release before 0.3.0 is retracted because of known security issues.

Import only from the public packages: `pkg/auth`, `pkg/config`, `pkg/types`, `pkg/models`, `pkg/modules/*`, `pkg/adapters/*` and `storage`. Everything under `internal/` is private.

### Trying what is on `main`

These docs follow the `main` branch. The SAML, Identity Provider, RBAC, Team and UI modules are there and not yet in a release. To use them now:

```bash
go get github.com/bete7512/goauth@main
```

### Working against a local checkout

```bash
go mod edit -replace github.com/bete7512/goauth=/absolute/path/to/goauth
go mod tidy
```

## Connect a database

### SQLite

```go
store, err := storage.NewGormStorage(storage.GormConfig{
    Dialect: types.DialectTypeSqlite,
    DSN: "auth.db",
})
if err != nil {
    return err
}
```

### PostgreSQL

```go
store, err := storage.NewGormStorage(storage.GormConfig{
    Dialect: types.DialectTypePostgres,
    DSN: os.Getenv("DATABASE_DSN"),
    MaxOpenConns: 25,
    MaxIdleConns: 5,
})
if err != nil {
    return err
}
```

Create the database and its user first, and use a DSN with the TLS settings your deployment needs.

### MySQL

```go
store, err := storage.NewGormStorage(storage.GormConfig{
    Dialect: types.DialectTypeMysql,
    DSN: os.Getenv("DATABASE_DSN"),
})
if err != nil {
    return err
}
```

Include `parseTime=true` in the DSN, for example `authuser:password@tcp(localhost:3306)/authdb?parseTime=true`.

### A GORM connection you already have

```go
store := storage.NewGormStorageFromDB(existingDB)
```

GoAuth closes the storage when it shuts down. If your application owns the connection, set `BorrowStorage: true` in `config.Config`.

## Create the tables

Opening the storage does not create any tables. Set `Migration: config.MigrationConfig{Auto: true}` to apply pending migrations when GoAuth starts, or generate the SQL and run it yourself. See [Migrations](migrations.md).

## Framework adapters

The `net/http` adapter, `pkg/adapters/stdhttp`, comes with GoAuth. The Gin, Chi and Fiber adapters are separate Go modules. Install the one you need:

```bash
go get github.com/bete7512/goauth/pkg/adapters/ginadapter@v0.3.0-beta.1
go get github.com/bete7512/goauth/pkg/adapters/chiadapter@v0.3.0-beta.1
go get github.com/bete7512/goauth/pkg/adapters/fiberadapter@v0.3.0-beta.1
```

Then register the routes once GoAuth is initialized:

```go
stdhttp.Register(mux, a)          // net/http
ginadapter.Register(router, a)    // Gin
chiadapter.Register(router, a)    // Chi
fiberadapter.Register(app, a)     // Fiber
```

With a local checkout, each adapter needs its own `replace` line pointing at its `pkg/adapters/...` directory. See [Gin](frameworks/gin.md).

## Email and SMS

GoAuth sends nothing until you add the [Notification module](modules/notification.md). It has senders for SMTP, SendGrid and Resend (email) and Twilio (SMS), in `github.com/bete7512/goauth/pkg/modules/notification/senders`.

## When something goes wrong

| What you see | What to do |
| --- | --- |
| `jwt secret key must be at least 32 characters` | Set `Security.JwtSecretKey` to at least 32 bytes and `Security.EncryptionKey` to at least 16. RS256 and ES256 also need signing keys. |
| Missing package or `go.sum` errors | Run `go mod tidy`. Install the adapter module if you use Gin, Chi or Fiber. |
| C compiler or cgo errors | They come from SQLite. Install your platform's build tools and keep `CGO_ENABLED=1`, or use PostgreSQL or MySQL. |
| Sign-up panics with a nil pointer | Set `Core: &config.CoreConfig{}` in the config, even when it is empty. |
| Constructors do not accept your arguments | You are following v0.2.x examples. See [Upgrading](upgrade.md). |
| A migration fails | Read the error and check `MigrationStatus`. Do not clear the migration table. See [Migrations](migrations.md). |

## Next

- [Quick Start](quickstart.md): a complete server.
- [Storage](storage.md): writing your own storage.
- [Security](security.md): tokens, cookies and keys.
