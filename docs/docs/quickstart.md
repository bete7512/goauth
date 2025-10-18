---
id: quickstart
title: Quick Start
sidebar_label: Quick Start
sidebar_position: 3
---

# Quick Start

Get up and running with GoAuth in minutes using the modular architecture. This guide shows you how to build a complete authentication system with the Core Module.

## Prerequisites

- **Go 1.21+** installed
- **GoAuth** installed (see [Installation Guide](installation.md))
- Basic knowledge of Go and web development
- A database (PostgreSQL, MySQL, or SQLite)

## Your First GoAuth Application

### 1. Project Setup

Create a new project:

```bash
mkdir goauth-demo
cd goauth-demo
go mod init goauth-demo
```

Install dependencies:

```bash
go get github.com/bete7512/goauth
```

### 2. Create main.go

Create `main.go` with the basic setup:

```go
package main

import (
    "context"
    "log"
    "net/http"
    "time"

    "github.com/bete7512/goauth/internal/storage"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/types"
)

func main() {
    // 1️⃣ CREATE STORAGE
    store, err := storage.NewStorage(config.StorageConfig{
        Driver:       "gorm",
        Dialect:      "sqlite", // or "postgres", "mysql"
        DSN:          "auth.db",
        AutoMigrate:  true,
        LogLevel:     "warn",
    })
    if err != nil {
        log.Fatalf("Storage error: %v", err)
    }
    defer store.Close()

    // 2️⃣ CREATE AUTH INSTANCE (Core Module auto-registered)
    a, err := auth.New(&config.Config{
        Storage:     store,
        AutoMigrate: true,
        BasePath:    "/api/v1",
        Security: types.SecurityConfig{
            JwtSecretKey:  "your-secret-key-min-32-chars!!!!",
            EncryptionKey: "your-encryption-key-32-chars!",
            Session: types.SessionConfig{
                Name:            "session_token",
                SessionTTL:      30 * 24 * time.Hour,
                AccessTokenTTL:  15 * time.Minute,
                RefreshTokenTTL: 7 * 24 * time.Hour,
            },
        },
        Core: &config.CoreConfig{
            RequireEmailVerification: false, // Set to true for email verification
            RequirePhoneVerification: false,
            RequireUserName:          false,
            RequirePhoneNumber:       false,
        },
    })
    if err != nil {
        log.Fatalf("Auth error: %v", err)
    }
    defer a.Close()

    // 3️⃣ REGISTER OPTIONAL MODULES (Add later as needed)
    // a.Use(notification.New(&notification.Config{...}))
    // a.Use(twofactor.New(&twofactor.TwoFactorConfig{...}))

    // 4️⃣ INITIALIZE
    if err := a.Initialize(context.Background()); err != nil {
        log.Fatalf("Initialize error: %v", err)
    }

    // 5️⃣ SERVE ROUTES
    mux := http.NewServeMux()
    for _, route := range a.Routes() {
        mux.Handle(route.Path, route.Handler)
    }

    // Add a simple home route
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"message": "GoAuth is running!"}`))
    })

    log.Println("🚀 Server starting on :8080")
    log.Println("📚 API available at: http://localhost:8080/api/v1")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

### 3. Run the Server

```bash
go run main.go
```

You should see:
```
🚀 Server starting on :8080
📚 API available at: http://localhost:8080/api/v1
```

## Testing the API

### 1. Register a New User

```bash
curl -X POST http://localhost:8080/api/v1/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

**Response:**
```json
{
  "message": "User registered successfully",
  "user": {
    "id": "uuid-here",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "email_verified": false
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 2. Login

```bash
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type": application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

**Response:**
```json
{
  "message": "Login successful",
  "user": {
    "id": "uuid-here",
    "email": "user@example.com",
    "first_name": "John"
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 3. Get User Profile (Protected Route)

Use the token from login/signup:

```bash
curl -X GET http://localhost:8080/api/v1/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Response:**
```json
{
  "id": "uuid-here",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe"
}
```

## Understanding the Three-Phase Pattern

### Phase 1: Create
```go
a, _ := auth.New(&config.Config{
    Storage:  store,
    Security: securityConfig,
    Core:     coreConfig,
})
```
- Creates auth instance
- **Core Module automatically registered**
- Configures security settings

### Phase 2: Register (Optional)
```go
a.Use(notification.New(&notification.Config{...}))
a.Use(twofactor.New(&twofactor.TwoFactorConfig{...}))
```
- Add optional modules
- Configure module-specific settings
- Modules can depend on each other

### Phase 3: Initialize
```go
a.Initialize(context.Background())
```
- Runs database migrations
- Initializes all modules
- Registers hooks and middlewares
- Builds route handlers

## Adding More Features

### Add Notification Module (Email/SMS)

```go
import (
    "github.com/bete7512/goauth/internal/modules/notification"
    "github.com/bete7512/goauth/internal/modules/notification/services/senders"
)

// After auth.New(), before Initialize()
a.Use(notification.New(&notification.Config{
    EmailSender: senders.NewSMTPEmailSender(&senders.SMTPConfig{
        Host:     "smtp.gmail.com",
        Port:     587,
        Username: "your-email@gmail.com",
        Password: "your-app-password",
    }),
    ServiceConfig: &services.NotificationConfig{
        AppName:      "My App",
        SupportEmail: "support@myapp.com",
    },
    EnableWelcomeEmail:       true,
    EnablePasswordResetEmail: true,
}))
```

Now users will receive emails for verification and password resets!

### Add Rate Limiting

```go
import "github.com/bete7512/goauth/internal/modules/ratelimiter"

a.Use(ratelimiter.New(&ratelimiter.RateLimiterConfig{
    RequestsPerMinute: 60,
    RequestsPerHour:   1000,
    BurstSize:         10,
}))
```

Protects your API from abuse.

### Add Two-Factor Authentication

```go
import "github.com/bete7512/goauth/internal/modules/twofactor"

a.Use(twofactor.New(&twofactor.TwoFactorConfig{
    Issuer:           "MyApp",
    Required:         false,
    BackupCodesCount: 10,
}))
```

Adds TOTP-based 2FA endpoints.

## Production Configuration

### Using PostgreSQL

```go
store, _ := storage.NewStorage(config.StorageConfig{
    Driver:       "gorm",
    Dialect:      "postgres",
    DSN:          "host=localhost user=postgres password=secret dbname=authdb sslmode=disable",
    AutoMigrate:  true,
    MaxOpenConns: 25,
    MaxIdleConns: 5,
})
```

### Using Environment Variables

```go
import "os"

security := types.SecurityConfig{
    JwtSecretKey:  os.Getenv("JWT_SECRET_KEY"),
    EncryptionKey: os.Getenv("ENCRYPTION_KEY"),
    Session: types.SessionConfig{
        AccessTokenTTL:  15 * time.Minute,
        RefreshTokenTTL: 7 * 24 * time.Hour,
    },
}
```

### CORS Configuration

```go
a, _ := auth.New(&config.Config{
    // ... other config
    CORS: &config.CORSConfig{
        Enabled:        true,
        AllowedOrigins: []string{"http://localhost:3000"},
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
    },
})
```

## Framework Integration Examples

### With Gin

```go
import "github.com/gin-gonic/gin"

r := gin.Default()

// Register GoAuth routes
for _, route := range a.Routes() {
    switch route.Method {
    case http.MethodGet:
        r.GET(route.Path, gin.WrapF(route.Handler))
    case http.MethodPost:
        r.POST(route.Path, gin.WrapF(route.Handler))
    case http.MethodPut:
        r.PUT(route.Path, gin.WrapF(route.Handler))
    case http.MethodDelete:
        r.DELETE(route.Path, gin.WrapF(route.Handler))
    }
}

r.Run(":8080")
```

### With Chi

```go
import "github.com/go-chi/chi/v5"

r := chi.NewRouter()

// Register GoAuth routes
for _, route := range a.Routes() {
    switch route.Method {
    case http.MethodGet:
        r.Get(route.Path, route.Handler)
    case http.MethodPost:
        r.Post(route.Path, route.Handler)
    case http.MethodPut:
        r.Put(route.Path, route.Handler)
    case http.MethodDelete:
        r.Delete(route.Path, route.Handler)
    }
}

http.ListenAndServe(":8080", r)
```

## Next Steps

Now that you have a working authentication system:

### Learn More
- **[Core Module](/docs/modules/core)** - Detailed Core Module documentation
- **[Notification Module](/docs/modules/notification)** - Add email/SMS notifications
- **[API Reference](/docs/api/endpoints)** - Complete API documentation
- **[Configuration](/docs/configuration/auth)** - Advanced configuration options

### Add Features
- **Two-Factor Authentication** - Enhance security
- **OAuth** - Add social login
- **Rate Limiting** - Protect your API
- **CSRF Protection** - Prevent CSRF attacks

### Production
- **[Security Best Practices](/docs/features/security)** - Secure your application
- **[Custom Storage](/docs/getting-started/custom-storage)** - Implement custom storage
- **[Examples](/docs/examples/basic-auth)** - More complete examples

## Troubleshooting

### Common Issues

**Database Connection Failed**
```
Error: failed to connect to database
```
- Check your DSN connection string
- Ensure database server is running
- Verify credentials

**Port Already in Use**
```
Error: listen tcp :8080: bind: address already in use
```
- Change port: `http.ListenAndServe(":8081", mux)`
- Or kill process using port 8080

**JWT Secret Too Short**
```
Error: JWT secret must be at least 32 characters
```
- Use a minimum 32-character secret key
- Generate secure keys: `openssl rand -base64 32`

### Getting Help

- 📖 [Documentation](/docs/intro)
- 🐛 [GitHub Issues](https://github.com/bete7512/goauth/issues)
- 💬 [Discussions](https://github.com/bete7512/goauth/discussions)

---

**Congratulations!** 🎉 You've built your first GoAuth application. Start adding modules to extend functionality as you need it.
