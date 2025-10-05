---
id: quickstart
title: Quick Start
sidebar_label: Quick Start
sidebar_position: 3
---

# Quick Start

Get up and running with GoAuth in minutes. This guide will walk you through creating a simple authentication system.

## Prerequisites

- Go 1.21+ installed
- GoAuth installed (see [Installation Guide](installation.md))
- Basic knowledge of Go and web development

## Project Setup

### 1. Create a new project

```bash
mkdir goauth-demo
cd goauth-demo
go mod init goauth-demo
```

### 2. Install dependencies

```bash
go get github.com/bete7512/goauth
go get github.com/gin-gonic/gin
```

### 3. Create the main application

Create `main.go`:

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/bete7512/goauth/internal/storage"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
)

func main() {
    // Storage
    store, err := storage.NewStorage(config.StorageConfig{
        Driver:      "gorm",
        Dialect:     "postgres",
        DSN:         "postgres://username:password@localhost/goauth?sslmode=disable",
        AutoMigrate: true,
    })
    if err != nil { log.Fatal(err) }
    defer store.Close()

    // Auth
    a, err := auth.New(&config.Config{
        Storage: store,
        Security: config.SecurityConfig{
            JwtSecretKey:  "your-32-byte-secret",
            EncryptionKey: "your-32-byte-secret",
        },
        AutoMigrate: true,
    })
    if err != nil { log.Fatal(err) }

    if err := a.Initialize(context.Background()); err != nil { log.Fatal(err) }

    // Serve routes
    mux := http.NewServeMux()
    for _, r := range a.Routes() {
        mux.Handle(r.Path, r.Handler)
    }
    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Database Setup

### 1. Create PostgreSQL database

```sql
CREATE DATABASE goauth;
CREATE USER goauth_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE goauth TO goauth_user;
```

### 2. Run migrations

GoAuth will automatically create the required tables on first run.

## Testing the Application

### 1. Start the server

```bash
go run main.go
```

### 2. Test registration

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123",
    "name": "John Doe"
  }'
```

### 3. Test login

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

### 4. Test protected route

Use the token from the login response:

```bash
curl -X GET http://localhost:8080/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## What's Happening?

1. **Registration**: Creates a new user account with hashed password
2. **Login**: Authenticates user and returns tokens
3. **Routes()**: You mount handlers returned by `a.Routes()` to your router
4. **Middleware**: Module middlewares are applied automatically during `Initialize`

## Next Steps

Now that you have a basic authentication system running:

- [Basic Authentication](getting-started/basic-auth.md) - Learn about authentication flows
- [OAuth Setup](getting-started/oauth-setup.md) - Add social login
- [Configuration](configuration/auth.md) - Customize your setup
- [Security Features](features/security.md) - Add rate limiting and CSRF protection

## Troubleshooting

### Common Issues

- **Database connection failed**: Check your PostgreSQL connection string
- **Port already in use**: Change the port in `r.Run(":8080")`
- **JWT errors**: Ensure your JWT secret is properly set

### Getting Help

- Check the [GitHub Issues](https://github.com/your-org/goauth/issues)
- Review the [Configuration Guide](configuration/auth.md)
- Join our [Discussions](https://github.com/your-org/goauth/discussions)
