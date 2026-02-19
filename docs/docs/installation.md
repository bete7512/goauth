---
id: installation
title: Installation
sidebar_label: Installation
sidebar_position: 2
---

# Installation

## Prerequisites

- **Go 1.25+** installed
- A Go module initialized (`go mod init`)
- A database (PostgreSQL, MySQL, or SQLite)

## Install

```bash
go get github.com/bete7512/goauth
```

## Database Setup

### SQLite (Development)

No setup needed:

```go
store, _ := storage.NewGormStorage(storage.GormConfig{
    Dialect: types.DialectTypeSqlite,
    DSN:     "auth.db",
})
```

### PostgreSQL (Production)

```sql
CREATE DATABASE authdb;
CREATE USER authuser WITH PASSWORD 'securepassword';
GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;
```

```go
store, _ := storage.NewGormStorage(storage.GormConfig{
    Dialect:      types.DialectTypePostgres,
    DSN:          "host=localhost user=authuser password=securepassword dbname=authdb sslmode=disable",
    MaxOpenConns: 25,
    MaxIdleConns: 5,
})
```

### MySQL

```sql
CREATE DATABASE authdb;
CREATE USER 'authuser'@'localhost' IDENTIFIED BY 'securepassword';
GRANT ALL PRIVILEGES ON authdb.* TO 'authuser'@'localhost';
```

```go
store, _ := storage.NewGormStorage(storage.GormConfig{
    Dialect: types.DialectTypeMysql,
    DSN:     "authuser:securepassword@tcp(localhost:3306)/authdb?parseTime=true",
})
```

### Existing GORM Instance

If you already have a `*gorm.DB`:

```go
store := storage.NewGormStorageFromDB(existingDB)
```

## Optional: Email & SMS

### SendGrid

```go
import "github.com/bete7512/goauth/internal/modules/notification/services/senders"

emailSender := senders.NewSendGridEmailSender(&senders.SendGridConfig{
    APIKey:      "your-sendgrid-api-key",
    DefaultFrom: "noreply@yourapp.com",
})
```

### SMTP

```go
emailSender := senders.NewSMTPEmailSender(&senders.SMTPConfig{
    Host:     "smtp.gmail.com",
    Port:     587,
    Username: "your-email@gmail.com",
    Password: "your-app-password",
})
```

### Twilio (SMS)

```go
smsSender := senders.NewTwilioSMSSender(&senders.TwilioConfig{
    AccountSID: "your-account-sid",
    AuthToken:  "your-auth-token",
    FromNumber: "+1234567890",
})
```

## Minimal Example

```go
package main

import (
    "context"
    "log"
    "net/http"
    "time"

    "github.com/bete7512/goauth/pkg/adapters/stdhttp"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/types"
    "github.com/bete7512/goauth/storage"
)

func main() {
    store, err := storage.NewGormStorage(storage.GormConfig{
        Dialect: types.DialectTypeSqlite,
        DSN:     "auth.db",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close()

    a, err := auth.New(&config.Config{
        Storage:     store,
        AutoMigrate: true,
        Security: types.SecurityConfig{
            JwtSecretKey:  "your-secret-key-min-32-chars!!",
            EncryptionKey: "your-encryption-key-32-chars!!",
            Session: types.SessionConfig{
                AccessTokenTTL:  15 * time.Minute,
                RefreshTokenTTL: 7 * 24 * time.Hour,
            },
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    defer a.Close()

    if err := a.Initialize(context.Background()); err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    stdhttp.Register(mux, a)
    log.Println("Server running on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Troubleshooting

**Module not found**
```bash
go mod tidy
go get github.com/bete7512/goauth
```

**Go version too old** — GoAuth requires Go 1.25+. Check with `go version`.

**SQLite requires CGO** — On Linux, install `build-essential`. On macOS, install Xcode CLI tools: `xcode-select --install`.

## Next Steps

- [Quick Start](quickstart.md) — Build your first auth system
- [Core Module](modules/core.md) — Core module details
