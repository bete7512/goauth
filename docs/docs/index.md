---
id: index
title: GoAuth Documentation
sidebar_label: Overview
slug: /overview
---

# GoAuth Documentation

Welcome to the comprehensive documentation for **GoAuth** - a modular, framework-agnostic authentication library for Go applications.

## 🎯 What is GoAuth?

GoAuth is a modern authentication library built with **modularity** at its core. Instead of a monolithic solution with every feature enabled by default, GoAuth lets you compose your authentication system using only the modules you need.

## 🚀 Quick Links

### Getting Started
- **[Introduction](/docs/intro)** - Learn about GoAuth's modular architecture
- **[Installation](/docs/installation)** - Get GoAuth installed in your project
- **[Quick Start](/docs/quickstart)** - Build your first auth system in minutes

### Modules

**Core Module** (Auto-registered)
- **[Core Module](/docs/modules/core)** - Essential authentication features

**Optional Modules**
- **[Notification Module](/docs/modules/notification)** - Email & SMS notifications
- **Two-Factor Module** - TOTP-based 2FA (docs coming soon)
- **OAuth Module** - Social login providers (docs coming soon)
- **Rate Limiter Module** - IP-based rate limiting (docs coming soon)
- **Captcha Module** - Bot protection (docs coming soon)
- **CSRF Module** - CSRF protection (docs coming soon)

### Reference
- **[API Endpoints](/docs/api/endpoints)** - Complete API documentation
- **[Configuration](/docs/configuration/auth)** - Configuration reference

## 🧩 Architecture Overview

```
┌──────────────────────────────────────┐
│         Your Application             │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│         GoAuth Instance              │
│  ┌────────────────────────────────┐ │
│  │      Core Module (Auto)        │ │
│  │  • User Registration           │ │
│  │  • Authentication              │ │
│  │  • JWT Sessions                │ │
│  │  • Profile Management          │ │
│  └────────────────────────────────┘ │
│                                      │
│  Optional Modules (Add as needed):  │
│  ┌─────────────┐ ┌──────────────┐  │
│  │Notification │ │  Two-Factor  │  │
│  └─────────────┘ └──────────────┘  │
│  ┌─────────────┐ ┌──────────────┐  │
│  │  OAuth      │ │ Rate Limiter │  │
│  └─────────────┘ └──────────────┘  │
│  ┌─────────────┐ ┌──────────────┐  │
│  │  Captcha    │ │    CSRF      │  │
│  └─────────────┘ └──────────────┘  │
└──────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│       Storage Layer (GORM,           │
│       MongoDB, or Custom)            │
└──────────────────────────────────────┘
```

## 📦 Core Features

### 🔐 Core Module (Always Included)

The Core Module is automatically registered and provides:

- **User Management**: Registration, login, logout, profile management
- **JWT Authentication**: Access tokens and refresh tokens
- **Password Security**: Bcrypt hashing, reset flows
- **Email Verification**: Send and verify email addresses
- **Phone Verification**: SMS-based phone verification
- **Availability Checking**: Real-time email/username/phone availability

### 🧩 Optional Modules

Add features as you need them:

| Module | Purpose | Key Features |
|--------|---------|--------------|
| **Notification** | Email/SMS | SendGrid, Twilio, SMTP, Resend support |
| **Two-Factor** | Enhanced security | TOTP, backup codes, QR generation |
| **OAuth** | Social login | Google, GitHub, Facebook, Microsoft, Apple |
| **Rate Limiter** | API protection | Per-IP rate limiting, configurable rules |
| **Captcha** | Bot protection | reCAPTCHA v3, Cloudflare Turnstile |
| **CSRF** | CSRF protection | Token-based protection, configurable |
| **Admin** | User management | Admin-only endpoints for user CRUD |
| **Magic Link** | Passwordless auth | Email-based passwordless login |

## 🎯 Three-Phase Usage Pattern

GoAuth follows a simple, predictable pattern:

```go
// 1️⃣ CREATE: Initialize with Core Module
a, _ := auth.New(&config.Config{
    Storage:  store,
    Security: securityConfig,
    // ... core config
})

// 2️⃣ REGISTER: Add optional modules
a.Use(notification.New(&notification.Config{...}))
a.Use(twofactor.New(&twofactor.TwoFactorConfig{...}))
a.Use(ratelimiter.New(&ratelimiter.RateLimiterConfig{...}))

// 3️⃣ INITIALIZE: Build routes, run migrations, wire everything
a.Initialize(context.Background())

// Then serve routes
routes := a.Routes()
```

## 🌐 Framework Agnostic

Works with **any** Go web framework:

```go
// Standard HTTP
mux := http.NewServeMux()
for _, route := range a.Routes() {
    mux.Handle(route.Path, route.Handler)
}

// Gin
r := gin.Default()
for _, route := range a.Routes() {
    r.POST(route.Path, gin.WrapF(route.Handler))
}

// Chi
router := chi.NewRouter()
for _, route := range a.Routes() {
    router.Post(route.Path, route.Handler)
}

// Fiber
app := fiber.New()
for _, route := range a.Routes() {
    app.Post(route.Path, adaptor.HTTPHandler(route.Handler))
}
```

## 🎣 Event-Driven

Subscribe to events for custom logic:

```go
// Hook into user signup
a.On(types.EventAfterSignup, func(ctx context.Context, e *types.Event) error {
    user := e.Data["user"]
    // Send to analytics, CRM, etc.
    return nil
})

// Custom validation before login
a.On(types.EventBeforeLogin, func(ctx context.Context, e *types.Event) error {
    // Your custom logic
    return nil
})
```

**Available Events:**
- `EventBeforeSignup` / `EventAfterSignup`
- `EventBeforeLogin` / `EventAfterLogin`
- `EventBeforePasswordReset` / `EventAfterPasswordReset`
- And many more...

Events are processed **asynchronously** with support for custom backends (Redis, RabbitMQ, Kafka).

## 📊 Storage Options

### Built-in GORM Support

```go
// PostgreSQL
store, _ := storage.NewStorage(config.StorageConfig{
    Driver:  "gorm",
    Dialect: "postgres",
    DSN:     "host=localhost user=postgres password=secret dbname=authdb",
})

// MySQL
store, _ := storage.NewStorage(config.StorageConfig{
    Driver:  "gorm",
    Dialect: "mysql",
    DSN:     "user:password@tcp(localhost:3306)/authdb?parseTime=true",
})

// SQLite
store, _ := storage.NewStorage(config.StorageConfig{
    Driver:  "gorm",
    Dialect: "sqlite",
    DSN:     "auth.db",
})
```

### Custom Storage

Implement your own storage layer:

```go
type CustomStorage struct {
    // Your implementation
}

func (s *CustomStorage) GetRepository(name string) interface{} {
    // Return repository
}

// Use custom storage
a, _ := auth.New(&config.Config{
    Storage: &CustomStorage{},
})
```

## 🛡️ Security Features

- **Password Hashing**: Bcrypt with configurable rounds
- **JWT Security**: Signed tokens with expiry
- **Rate Limiting**: Per-IP request limits (optional module)
- **CSRF Protection**: Token-based protection (optional module)
- **Bot Protection**: reCAPTCHA & Turnstile (optional module)
- **Two-Factor Auth**: TOTP with backup codes (optional module)

## 📚 Documentation Sections

### For Beginners
1. **[Introduction](/docs/intro)** - Understand GoAuth's philosophy
2. **[Installation](/docs/installation)** - Install the library
3. **[Quick Start](/docs/quickstart)** - Build your first system
4. **[Core Module](/docs/modules/core)** - Learn the essentials

### For Developers
1. **[Modules](/docs/modules/core)** - Detailed module documentation
2. **[API Reference](/docs/api/endpoints)** - Complete API docs
3. **[Configuration](/docs/configuration/auth)** - Configuration options
4. **[Examples](/docs/examples/basic-auth)** - Working examples

### For Advanced Users
1. **[Custom Storage](/docs/getting-started/custom-storage)** - Implement custom storage
2. **[Event System](/docs/intro#event-driven-architecture)** - Hook into events
3. **[Custom Modules](/docs/intro#creating-custom-modules)** - Build your own modules

## 🎨 Use Cases

### Startups & MVPs
```go
// Simple, fast setup with Core Module
a, _ := auth.New(&config.Config{...})
a.Initialize(context.Background())
```

### Growing Applications
```go
// Add features as you need them
a, _ := auth.New(&config.Config{...})
a.Use(notification.New(&notification.Config{...}))
a.Use(ratelimiter.New(&ratelimiter.RateLimiterConfig{...}))
a.Initialize(context.Background())
```

### Enterprise Applications
```go
// Full feature set
a, _ := auth.New(&config.Config{...})
a.Use(notification.New(&notification.Config{...}))
a.Use(twofactor.New(&twofactor.TwoFactorConfig{...}))
a.Use(oauth.New(&oauth.OAuthConfig{...}))
a.Use(ratelimiter.New(&ratelimiter.RateLimiterConfig{...}))
a.Use(captcha.New(&captcha.CaptchaConfig{...}))
a.Use(csrf.New(&csrf.CSRFConfig{...}))
a.Use(admin.New(&admin.AdminConfig{...}))
a.Initialize(context.Background())
```

## 🚀 Next Steps

### New to GoAuth?
1. Read the [Introduction](/docs/intro)
2. Follow the [Installation Guide](/docs/installation)
3. Complete the [Quick Start Tutorial](/docs/quickstart)

### Ready to Build?
1. Learn about the [Core Module](/docs/modules/core)
2. Explore [Optional Modules](/docs/modules/notification)
3. Check [API Documentation](/docs/api/endpoints)

### Need Help?
- Browse [Examples](/docs/examples/basic-auth)
- Check [GitHub Issues](https://github.com/bete7512/goauth/issues)
- Join [GitHub Discussions](https://github.com/bete7512/goauth/discussions)

---

**GoAuth** - Modular authentication for modern Go applications. 🧩
