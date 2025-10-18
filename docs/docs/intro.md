---
id: intro
title: Introduction
sidebar_label: Introduction
slug: /
---

# Welcome to GoAuth

GoAuth is a **modular, framework-agnostic** authentication library for Go applications. Built with flexibility at its core, GoAuth lets you compose exactly the authentication features you need through a powerful plug-and-play module system.

## What is GoAuth?

GoAuth provides a comprehensive authentication solution that scales from simple user authentication to complex enterprise setups. Unlike monolithic auth libraries, GoAuth uses a **modular architecture** where you start with core authentication and add features as needed.

## 🎯 Core Philosophy

**Build Only What You Need**  
Start with the Core Module (auto-registered) for essential authentication, then add modules like Two-Factor, OAuth, Rate Limiting, or Notifications as your requirements grow.

**Framework Agnostic**  
Works seamlessly with Gin, Echo, Chi, Fiber, Gorilla Mux, standard HTTP, and any Go web framework through clean HTTP handlers.

**Production Ready**  
Battle-tested with comprehensive error handling, async event processing, extensive testing, and auto-generated API documentation.

## ✨ Key Features

### 🧩 Modular Architecture
- **Plug-and-Play Modules**: Add only the features you need
- **Clean Dependencies**: Modules declare their dependencies explicitly
- **Event-Driven**: Powerful hook system for customization
- **Easy to Extend**: Create custom modules with provided scaffolding

### 🔐 Core Module (Auto-Registered)
The foundation of GoAuth, automatically included:
- User registration & authentication
- JWT-based sessions with refresh tokens
- Profile management
- Password reset & email verification
- Phone verification support
- Availability checking (email, username, phone)

### 📦 Optional Modules
Extend functionality as needed:
- **Notification**: Email/SMS with SendGrid, Twilio, SMTP, Resend
- **Two-Factor**: TOTP-based 2FA with backup codes
- **OAuth**: Social login (Google, GitHub, Facebook, Microsoft, Apple, Discord)
- **Rate Limiter**: IP-based rate limiting with configurable rules
- **Captcha**: reCAPTCHA v3 and Cloudflare Turnstile protection
- **CSRF**: Token-based CSRF protection
- **Admin**: Admin-only endpoints for user management
- **Magic Link**: Passwordless authentication via email

### 🔧 Technical Features
- **Multi-Framework Support**: Gin, Echo, Chi, Fiber, standard HTTP, and more
- **Database Agnostic**: PostgreSQL, MySQL, MongoDB, SQLite via GORM or custom storage
- **Async Events**: Built-in event bus with async processing
- **Custom Storage**: Bring your own database layer
- **Swagger/OpenAPI**: Auto-generated API documentation
- **Comprehensive Testing**: Unit, integration, and benchmark tests

## 🚀 Quick Example

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
    // 1. Create storage
    store, _ := storage.NewStorage(config.StorageConfig{
        Driver:  "gorm",
        Dialect: "sqlite",
        DSN:     "auth.db",
    })
    defer store.Close()

    // 2. Create auth instance (Core module auto-registered)
    a, _ := auth.New(&config.Config{
        Storage:     store,
        AutoMigrate: true,
        BasePath:    "/api/v1",
        Security: types.SecurityConfig{
            JwtSecretKey:  "your-secret-key-min-32-chars!!",
            EncryptionKey: "your-encryption-key-32-chars!!",
            Session: types.SessionConfig{
                AccessTokenTTL:  15 * time.Minute,
                RefreshTokenTTL: 7 * 24 * time.Hour,
            },
        },
    })
    defer a.Close()

    // 3. Register optional modules (BEFORE Initialize)
    // a.Use(twofactor.New(&twofactor.TwoFactorConfig{...}))
    // a.Use(ratelimiter.New(&ratelimiter.RateLimiterConfig{...}))

    // 4. Initialize all modules
    a.Initialize(context.Background())

    // 5. Serve routes
    mux := http.NewServeMux()
    for _, route := range a.Routes() {
        mux.Handle(route.Path, route.Handler)
    }
    
    log.Println("Server running on :8080")
    http.ListenAndServe(":8080", mux)
}
```

## 🎯 Three-Phase Pattern

GoAuth uses a simple three-phase initialization:

1. **Create**: `auth.New()` - Create auth instance, Core module auto-registered
2. **Register**: `auth.Use(module)` - Add optional modules
3. **Initialize**: `auth.Initialize()` - Run migrations, build routes, wire everything together

```go
// Phase 1: Create
a, _ := auth.New(&config.Config{...})

// Phase 2: Register modules
a.Use(notification.New(&notification.Config{...}))
a.Use(twofactor.New(&twofactor.TwoFactorConfig{...}))

// Phase 3: Initialize
a.Initialize(context.Background())

// Then serve routes
routes := a.Routes()
```

## 🧩 Available Modules

| Module | Description | Status |
|--------|-------------|--------|
| **Core** | User auth, JWT sessions, profiles, verification | Auto-registered |
| **Notification** | Email/SMS with multiple providers | ✅ Available |
| **Two-Factor** | TOTP-based 2FA with backup codes | ✅ Available |
| **OAuth** | Social login providers | ✅ Available |
| **Rate Limiter** | IP-based rate limiting | ✅ Available |
| **Captcha** | reCAPTCHA v3, Cloudflare Turnstile | ✅ Available |
| **CSRF** | Token-based CSRF protection | ✅ Available |
| **Admin** | Admin user management endpoints | ✅ Available |
| **Magic Link** | Passwordless authentication | ✅ Available |

## 🎣 Event-Driven Architecture

Subscribe to events for custom logic:

```go
import "github.com/bete7512/goauth/pkg/types"

// Hook into signup
a.On(types.EventAfterSignup, func(ctx context.Context, e *types.Event) error {
    user := e.Data["user"]
    log.Printf("New user: %+v", user)
    
    // Send to analytics, CRM, etc.
    return nil
})

// Enforce custom validation
a.On(types.EventBeforeLogin, func(ctx context.Context, e *types.Event) error {
    // Add custom logic before login
    return nil
})
```

Events are processed **asynchronously** by default. You can provide custom async backends (Redis, RabbitMQ, Kafka, etc.).

## 🌐 Framework Integration

Works with any Go web framework:

```go
// Standard HTTP
for _, route := range a.Routes() {
    mux.Handle(route.Path, route.Handler)
}

// Gin
for _, route := range a.Routes() {
    r.POST(route.Path, gin.WrapF(route.Handler))
}

// Chi
for _, route := range a.Routes() {
    router.Post(route.Path, route.Handler)
}
```

See [Framework Integration](frameworks/gin.md) for detailed examples.

## 📚 Documentation Structure

- **[Installation](installation.md)** - Get GoAuth installed
- **[Quick Start](quickstart.md)** - Get up and running in minutes
- **[Modules](modules/core.md)** - Detailed module documentation
  - [Core Module](modules/core.md) - Essential authentication
  - [Notification Module](modules/notification.md) - Email/SMS
  - More modules coming...
- **[API Reference](api/endpoints.md)** - Complete API documentation
- **[Configuration](configuration/auth.md)** - Configuration guide

## 🎨 Why Modular?

**Traditional Approach (Monolithic):**
```go
// All features included, whether you use them or not
auth := bigauthlib.New(massiveConfig)
// 🔴 Bloated, complex configuration, hard to maintain
```

**GoAuth Approach (Modular):**
```go
// Start simple
a, _ := auth.New(&config.Config{...})  // Core only

// Add what you need, when you need it
a.Use(twofactor.New(&twofactor.TwoFactorConfig{...}))  // ✅
a.Use(ratelimiter.New(&ratelimiter.RateLimiterConfig{...}))  // ✅

// Clean, maintainable, scalable
a.Initialize(context.Background())
```

## 🆚 Comparison

| Feature | GoAuth | Traditional Auth Libs |
|---------|--------|----------------------|
| **Architecture** | Modular, plug-and-play | Monolithic |
| **Framework Support** | Any Go framework | Often framework-specific |
| **Customization** | Event system + modules | Limited hooks |
| **Learning Curve** | Gentle, start simple | Steep, complex config |
| **Bundle Size** | Only what you use | Everything included |
| **Extensibility** | Easy custom modules | Difficult |

## 🚀 Getting Started

Ready to build secure authentication with GoAuth?

1. **[Install GoAuth](installation.md)** - Get the library installed
2. **[Quick Start Tutorial](quickstart.md)** - Build your first auth system
3. **[Explore Modules](modules/core.md)** - Learn about available modules
4. **[See Examples](examples/basic-auth.md)** - Complete working examples

## 💡 Use Cases

**Startups & MVPs**  
Start with Core Module for rapid development, add features as you scale.

**Enterprise Applications**  
Full feature set with Two-Factor, OAuth, Admin module, and custom integrations.

**Microservices**  
Lightweight, framework-agnostic design perfect for distributed systems.

**API Services**  
JWT-based authentication with comprehensive API documentation.

## 🤝 Community & Support

- **GitHub**: [github.com/bete7512/goauth](https://github.com/bete7512/goauth)
- **Issues**: Report bugs and request features
- **Discussions**: Join the community discussion
- **Documentation**: This site contains comprehensive guides

## 🎯 Next Steps

Choose your path:

- **New to GoAuth?** → [Installation Guide](installation.md)
- **Want to get started quickly?** → [Quick Start Tutorial](quickstart.md)
- **Need specific features?** → [Modules Documentation](modules/core.md)
- **Looking for API docs?** → [API Reference](api/endpoints.md)

---

**GoAuth** - Build authentication your way, one module at a time. 🧩
