---
id: installation
title: Installation
sidebar_label: Installation
sidebar_position: 2
---

# Installation

GoAuth requires Go 1.26 or later. The built-in GORM storage supports PostgreSQL, MySQL, and SQLite. SQLite uses CGO and needs a C compiler.

## Install

```bash
go get github.com/bete7512/goauth@v0.3.0-beta.1
```

These docs follow the current repository API, including unreleased changes. For local development against a checkout:

```bash
go mod edit -replace github.com/bete7512/goauth=/absolute/path/to/go-auth
go mod tidy
```

The [Quick Start](quickstart.md) contains a complete, runnable server. Imports under `internal/` are private; use `pkg/auth`, `pkg/config`, `pkg/types`, `pkg/models`, `pkg/modules/*`, and `storage`.

## Database Setup

### SQLite (Development)

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

Create the application database and credentials before starting. Use a DSN with the TLS settings appropriate to your deployment.

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

Include `parseTime=true` in a MySQL DSN, for example `authuser:password@tcp(localhost:3306)/authdb?parseTime=true` for a local database.

### Existing GORM Instance

```go
store := storage.NewGormStorageFromDB(existingDB)
```

Set `config.Config.BorrowStorage: true` when your application retains connection ownership. Otherwise `Auth.Close` closes the underlying connection. These snippets use the public `github.com/bete7512/goauth/storage` package.

## Migrations

Creating storage does not apply all module schemas. Register modules and choose either `Migration.Auto: true` or explicit migration management. Each module embeds versioned SQL for the supported dialects. See [Migration management](migrations.md), including checksums, locking, and dirty migration records.

## Framework Adapters

`pkg/adapters/stdhttp` ships in the root module. Install an optional adapter separately:

```bash
go get github.com/bete7512/goauth/pkg/adapters/ginadapter@v0.3.0-beta.1
go get github.com/bete7512/goauth/pkg/adapters/chiadapter@v0.3.0-beta.1
go get github.com/bete7512/goauth/pkg/adapters/fiberadapter@v0.3.0-beta.1
```

For a local checkout, each optional adapter also needs its own replacement pointing to its `pkg/adapters/...` directory. See [Framework integration](frameworks/gin.md).

## Optional: Email & SMS

Import `github.com/bete7512/goauth/pkg/modules/notification/senders`. Built-in integrations include SMTP, SendGrid, and Resend for email, and Twilio for SMS. Register them through `notification.Config`; [Notification](modules/notification.md) covers sender configuration, branding, and templates.

## Troubleshooting

- **Missing imports:** run `go mod tidy`; install the optional adapter module if needed.
- **Old constructor signatures:** remove second storage arguments and follow [Upgrading](upgrade.md).
- **Invalid config:** provide storage, a JWT secret of at least 32 bytes, and an encryption secret of at least 16 bytes. Additional signing keys are required for RS256/ES256.
- **SQLite compiler errors:** install your platform's C build toolchain and enable CGO.
- **Migration failure:** inspect the error and migration status rather than clearing the migration table. See [Migration management](migrations.md).

## Next Steps

- [Quick Start](quickstart.md)
- [Custom storage](storage.md)
- [Security configuration](security.md)
