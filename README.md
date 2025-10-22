# GoAuth 🔐

[![Go Report Card](https://goreportcard.com/badge/github.com/bete7512/goauth)](https://goreportcard.com/report/github.com/bete7512/goauth)
[![Go Version](https://img.shields.io/github/go-mod/go-version/bete7512/goauth)](https://go.dev/)
[![License](https://img.shields.io/github/license/bete7512/goauth)](LICENSE)
[![Release](https://img.shields.io/github/v/release/bete7512/goauth)](https://github.com/bete7512/goauth/releases)
[![CI/CD](https://img.shields.io/github/actions/workflow/status/bete7512/goauth/ci.yml?branch=main)](https://github.com/bete7512/goauth/actions)
[![Coverage](https://img.shields.io/codecov/c/github/bete7512/goauth)](https://codecov.io/gh/bete7512/goauth)

A **modular, framework-agnostic** authentication library for Go. GoAuth provides a flexible authentication system that works seamlessly across multiple web frameworks and allows you to compose features using a powerful modular architecture.

## 🎯 Why GoAuth?

**Built for Flexibility**  
Unlike monolithic auth libraries, GoAuth uses a modular architecture where you only include what you need. Start with core authentication and add features like 2FA, OAuth, rate limiting, or CSRF protection as modules.

**Framework Agnostic**  
Works with Gin, Echo, Chi, Fiber, Gorilla Mux, standard HTTP, and more. One library, any framework.


## ✨ Features

### 🧩 Modular Architecture
- **Plug-and-Play Modules**: Add only the features you need
- **Clean Dependencies**: Modules declare their dependencies explicitly
- **Event-Driven**: Powerful hook system for customization
- **Easy to Extend**: Create custom modules with provided scaffolding

### 🔐 Core Module (Auto-Registered)
- User registration & authentication
- JWT-based sessions with refresh tokens
- Profile management
- Password reset & email verification
- Phone verification support
- Availability checking (email, username, phone)
- Extended user attributes

### 📦 Available Modules
- **Notification**: Email/SMS notifications with multiple providers (SendGrid, Twilio, SMTP, Resend)
- **Two-Factor**: TOTP-based 2FA with backup codes
- **OAuth**: Social login (Google, GitHub, Facebook, Microsoft, Apple, Discord)
- **Rate Limiter**: IP-based rate limiting with configurable rules
- **Captcha**: reCAPTCHA v3 and Cloudflare Turnstile protection
- **CSRF**: Token-based CSRF protection
- **Admin**: Admin-only endpoints for user management
- **Magic Link**: Passwordless authentication via email

### 🔧 Technical Features
- **Multi-Framework Support**: Gin, Echo, Chi, Fiber, Gorilla Mux, standard HTTP
- **Database Agnostic**: PostgreSQL, MySQL, MongoDB, SQLite via GORM or custom storage
- **Async Events**: Built-in event bus with async processing (supports custom backends)
- **Custom Storage**: Bring your own database layer
- **Swagger/OpenAPI**: Auto-generated API documentation
- **Comprehensive Testing**: Unit, integration, and benchmark tests
- **Production Ready**: Structured logging, error handling, graceful shutdown

## 🚀 Quick Start

### Installation

```bash
go get github.com/bete7512/goauth
```

### Basic Usage

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
    // 1. Create storage (GORM + Postgres)
    store, err := storage.NewStorage(config.StorageConfig{
        Driver:       "gorm",
        Dialect:      "postgres",
        DSN:          "host=localhost user=postgres password=secret dbname=authdb sslmode=disable",
        AutoMigrate:  true,
        LogLevel:     "warn",
        MaxOpenConns: 25,
        MaxIdleConns: 5,
    })
    if err != nil {
        log.Fatalf("Storage error: %v", err)
    }
    defer store.Close()

    // 2. Create auth instance (core module auto-registered)
    a, err := auth.New(&config.Config{
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
        Core: &config.CoreConfig{
            RequireEmailVerification: true,
            RequirePhoneVerification: false,
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    defer a.Close()

    // 3. Register optional modules (BEFORE Initialize)
    // See "Adding Modules" section below

    // 4. Initialize (runs migrations, builds routes, registers hooks)
    if err := a.Initialize(context.Background()); err != nil {
        log.Fatal(err)
    }

    // 5. Serve routes
    mux := http.NewServeMux()
    for _, route := range a.Routes() {
        mux.Handle(route.Path, route.Handler)
    }
    
    log.Println("Server running on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## 🧩 Modular Architecture

GoAuth uses a three-phase initialization pattern:

1. **Creation**: `auth.New()` creates the auth instance with core configuration
2. **Registration**: `auth.Use(module)` registers optional modules
3. **Initialization**: `auth.Initialize()` runs migrations, builds routes, and wires everything together

### Core Module (Auto-Registered)

The core module is automatically registered when you create an auth instance. It provides:

- `POST /signup` - User registration
- `POST /login` - User authentication  
- `POST /logout` - User logout
- `GET /me` - Get current user
- `GET /profile` - Get user profile
- `PUT /profile` - Update user profile
- `PUT /change-password` - Change password
- `POST /forgot-password` - Request password reset
- `POST /reset-password` - Reset password
- `POST /send-verification-email` - Send email verification
- `GET /verify-email` - Verify email
- `POST /send-verification-phone` - Send phone verification
- `POST /verify-phone` - Verify phone
- `POST /availability/email` - Check email availability
- `POST /availability/username` - Check username availability
- `POST /availability/phone` - Check phone availability

### Adding Modules

Add modules using the `Use()` method before calling `Initialize()`:

#### Notification Module (Email & SMS)

```go
import (
    "github.com/bete7512/goauth/internal/modules/notification"
    "github.com/bete7512/goauth/internal/modules/notification/services/senders"
)

a.Use(notification.New(&notification.Config{
    EmailSender: senders.NewSendGridEmailSender(&senders.SendGridConfig{
        APIKey:          "your-sendgrid-api-key",
        DefaultFrom:     "noreply@yourapp.com",
        DefaultFromName: "Your App",
    }),
    ServiceConfig: &services.NotificationConfig{
        AppName:      "Your App",
        SupportEmail: "support@yourapp.com",
    },
    EnableWelcomeEmail:        true,
    EnablePasswordResetEmail:  true,
    EnableLoginAlerts:         true,
    EnablePasswordChangeAlert: true,
}))
```

#### Two-Factor Authentication

```go
import "github.com/bete7512/goauth/internal/modules/twofactor"

a.Use(twofactor.New(&twofactor.TwoFactorConfig{
    Issuer:           "MyApp",
    Required:         false,
    BackupCodesCount: 10,
    CodeLength:       8,
}))
```

Adds routes:
- `POST /2fa/setup` - Initialize 2FA setup
- `POST /2fa/verify` - Verify and enable 2FA
- `POST /2fa/disable` - Disable 2FA
- `GET /2fa/status` - Get 2FA status

#### Rate Limiter

```go
import "github.com/bete7512/goauth/internal/modules/ratelimiter"

a.Use(ratelimiter.New(&ratelimiter.RateLimiterConfig{
    RequestsPerMinute: 60,
    RequestsPerHour:   1000,
    BurstSize:         10,
}))
```

Automatically applies IP-based rate limiting to all endpoints.

#### Captcha Protection

```go
import "github.com/bete7512/goauth/internal/modules/captcha"

// Google reCAPTCHA v3
a.Use(captcha.New(&captcha.CaptchaConfig{
    Provider:           "google",
    RecaptchaSiteKey:   "your-site-key",
    RecaptchaSecretKey: "your-secret-key",
    RecaptchaThreshold: 0.5,
    ApplyToRoutes:      []string{"core.login", "core.signup"},
}))

// Or Cloudflare Turnstile
a.Use(captcha.New(&captcha.CaptchaConfig{
    Provider:           "cloudflare",
    TurnstileSiteKey:   "your-site-key",
    TurnstileSecretKey: "your-secret-key",
    ApplyToRoutes:      []string{"core.login", "core.signup"},
}))
```

#### CSRF Protection

```go
import "github.com/bete7512/goauth/internal/modules/csrf"

a.Use(csrf.New(&csrf.CSRFConfig{
    TokenLength:      32,
    TokenExpiry:      3600,
    Secure:           true,
    HTTPOnly:         true,
    SameSite:         http.SameSiteStrictMode,
    ProtectedMethods: []string{"POST", "PUT", "DELETE", "PATCH"},
}))
```

Adds route:
- `GET /csrf-token` - Get CSRF token

#### Complete Example with Multiple Modules

```go
func main() {
    store, _ := storage.NewStorage(config.StorageConfig{ /* ... */ })
    
    a, _ := auth.New(&config.Config{ /* ... */ })

    // Add notification support
    a.Use(notification.New(&notification.Config{
        EmailSender: senders.NewSendGridEmailSender(/* ... */),
        EnableWelcomeEmail:       true,
        EnablePasswordResetEmail: true,
    }))

    // Add two-factor authentication
    a.Use(twofactor.New(&twofactor.TwoFactorConfig{
        Issuer:   "MyApp",
        Required: false,
    }))

    // Add rate limiting
    a.Use(ratelimiter.New(&ratelimiter.RateLimiterConfig{
        RequestsPerMinute: 60,
        RequestsPerHour:   1000,
    }))

    // Add captcha protection
    a.Use(captcha.New(&captcha.CaptchaConfig{
        Provider:           "google",
        RecaptchaSiteKey:   os.Getenv("RECAPTCHA_SITE_KEY"),
        RecaptchaSecretKey: os.Getenv("RECAPTCHA_SECRET_KEY"),
        ApplyToRoutes:      []string{"core.login", "core.signup"},
    }))

    // Add CSRF protection
    a.Use(csrf.New(&csrf.CSRFConfig{
        TokenLength: 32,
        TokenExpiry: 3600,
        Secure:      true,
    }))

    // Initialize all modules
    a.Initialize(context.Background())

    // Serve
    mux := http.NewServeMux()
    for _, route := range a.Routes() {
        mux.Handle(route.Path, route.Handler)
    }
    http.ListenAndServe(":8080", mux)
}
```

## 📖 Framework Integration

GoAuth works with any Go web framework through route registration:

### Standard HTTP

```go
mux := http.NewServeMux()
for _, route := range a.Routes() {
    mux.Handle(route.Path, route.Handler)
}
http.ListenAndServe(":8080", mux)
```

### Gin

```go
import "github.com/gin-gonic/gin"

r := gin.Default()
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

### Echo

```go
import (
    "github.com/labstack/echo/v4"
    "net/http"
)

e := echo.New()
for _, route := range a.Routes() {
    switch route.Method {
    case http.MethodGet:
        e.GET(route.Path, echo.WrapHandler(http.HandlerFunc(route.Handler)))
    case http.MethodPost:
        e.POST(route.Path, echo.WrapHandler(http.HandlerFunc(route.Handler)))
    // ... other methods
    }
}
e.Start(":8080")
```

### Chi

```go
import "github.com/go-chi/chi/v5"

r := chi.NewRouter()
for _, route := range a.Routes() {
    switch route.Method {
    case http.MethodGet:
        r.Get(route.Path, route.Handler)
    case http.MethodPost:
        r.Post(route.Path, route.Handler)
    // ... other methods
    }
}
http.ListenAndServe(":8080", r)
```

### Fiber

```go
import (
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/adaptor"
)

app := fiber.New()
for _, route := range a.Routes() {
    switch route.Method {
    case http.MethodGet:
        app.Get(route.Path, adaptor.HTTPHandler(route.Handler))
    case http.MethodPost:
        app.Post(route.Path, adaptor.HTTPHandler(route.Handler))
    // ... other methods
    }
}
app.Listen(":8080")
```

## 🎣 Event System

GoAuth has a powerful event-driven architecture. Subscribe to events for custom logic:

```go
import "github.com/bete7512/goauth/pkg/types"

// Hook into user signup
a.On(types.EventBeforeSignup, func(ctx context.Context, e *types.Event) error {
    log.Printf("User about to signup: %+v", e.Data)
    // Add custom validation, external API calls, etc.
    return nil
})

a.On(types.EventAfterSignup, func(ctx context.Context, e *types.Event) error {
    log.Printf("User signed up: %+v", e.Data)
    // Send to analytics, CRM, etc.
    return nil
})

// Hook into login events
a.On(types.EventAfterLogin, func(ctx context.Context, e *types.Event) error {
    user := e.Data["user"]
    log.Printf("User logged in: %+v", user)
    return nil
})
```

### Available Events

**Core Events:**
- `EventBeforeSignup` / `EventAfterSignup`
- `EventBeforeLogin` / `EventAfterLogin`
- `EventBeforeLogout` / `EventAfterLogout`
- `EventBeforePasswordReset` / `EventAfterPasswordReset`
- `EventBeforePasswordChange` / `EventAfterPasswordChange`
- `EventBeforeProfileUpdate` / `EventAfterProfileUpdate`
- `EventBeforeEmailVerification` / `EventAfterEmailVerification`
- `EventBeforePhoneVerification` / `EventAfterPhoneVerification`

**Module Events:**
- Two-Factor: `EventBefore2FASetup`, `EventAfter2FAVerify`, `EventAfter2FADisable`
- Notification: `EventBeforeSendEmail`, `EventAfterSendEmail`, `EventBeforeSendSMS`, `EventAfterSendSMS`

### Async Event Processing

Events are processed asynchronously by default. You can provide custom async backends:

```go
// Custom async backend (e.g., Redis, RabbitMQ, Kafka)
type MyAsyncBackend struct {
    // Your implementation
}

func (b *MyAsyncBackend) Publish(ctx context.Context, eventType types.EventType, event *types.Event) error {
    // Publish to your message queue
    return nil
}

func (b *MyAsyncBackend) Close() error {
    return nil
}

func (b *MyAsyncBackend) Name() string {
    return "my-backend"
}

// Use custom backend
a, _ := auth.New(&config.Config{
    AsyncBackend: &MyAsyncBackend{},
    // ... other config
})
```

## 📄 API Documentation (Swagger)

Generate Swagger/OpenAPI documentation automatically:

```go
// After initialization
err := a.EnableSwagger(types.SwaggerConfig{
    Title:       "My API",
    Description: "My API Documentation",
    Version:     "1.0.0",
    Path:        "/docs",
    Servers: []types.SwaggerServer{
        {URL: "http://localhost:8080", Description: "Development"},
        {URL: "https://api.myapp.com", Description: "Production"},
    },
})

// Swagger UI available at: http://localhost:8080/docs
```

## 🗄️ Storage Configuration

### Using GORM (Built-in)

```go
// PostgreSQL
store, _ := storage.NewStorage(config.StorageConfig{
    Driver:       "gorm",
    Dialect:      "postgres",
    DSN:          "host=localhost user=postgres password=secret dbname=authdb",
    AutoMigrate:  true,
    MaxOpenConns: 25,
    MaxIdleConns: 5,
})

// MySQL
store, _ := storage.NewStorage(config.StorageConfig{
    Driver:   "gorm",
    Dialect:  "mysql",
    DSN:      "user:password@tcp(localhost:3306)/authdb?parseTime=true",
})

// SQLite
store, _ := storage.NewStorage(config.StorageConfig{
    Driver:  "gorm",
    Dialect: "sqlite",
    DSN:     "auth.db",
})

// MongoDB (via custom driver)
store, _ := storage.NewStorage(config.StorageConfig{
    Driver: "mongo",
    DSN:    "mongodb://localhost:27017/authdb",
})
```

### Custom Storage Layer

Implement your own storage:

```go
type MyStorage struct {
    // Your implementation
}

func (s *MyStorage) GetRepository(name string) interface{} {
    // Return repository for the given name
}

func (s *MyStorage) Migrate(ctx context.Context, models []interface{}) error {
    // Run migrations
}

func (s *MyStorage) Close() error {
    return nil
}

// Use custom storage
a, _ := auth.New(&config.Config{
    Storage: &MyStorage{},
    // ...
})
```

## 🔧 Configuration Reference

### Core Configuration

```go
&config.Config{
    Storage:     store,              // Storage implementation
    AutoMigrate: true,               // Auto-run migrations
    BasePath:    "/api/v1",          // API base path
    Logger:      customLogger,       // Custom logger (optional)
    AsyncBackend: customBackend,     // Custom async backend (optional)
    
    Security: types.SecurityConfig{
        JwtSecretKey:  "secret-32-chars-minimum!!!!",
        EncryptionKey: "encrypt-32-chars-minimum!!!",
        Session: types.SessionConfig{
            Name:            "session_token",
            SessionTTL:      30 * 24 * time.Hour,
            AccessTokenTTL:  15 * time.Minute,
            RefreshTokenTTL: 7 * 24 * time.Hour,
        },
    },
    
    Core: &config.CoreConfig{
        RequireEmailVerification: true,
        RequirePhoneVerification: false,
        RequireUserName:          false,
        RequirePhoneNumber:       false,
        UniquePhoneNumber:        true,
    },
    
    FrontendConfig: &config.FrontendConfig{
        URL:                     "http://localhost:3000",
        Domain:                  "localhost",
        ResetPasswordPath:       "/reset-password",
        VerifyEmailCallbackPath: "/verify-email",
        LoginPath:               "/login",
    },
    
    CORS: &config.CORSConfig{
        Enabled:        true,
        AllowedOrigins: []string{"http://localhost:3000"},
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
    },
}
```

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run integration tests
go test -tags=integration ./tests/integration/...

# Run benchmarks
go test -bench=. -benchmem ./...
```

## 📚 Documentation

- [Module Documentation](internal/modules/README.md) - Detailed module documentation
- [Examples](examples/) - Working examples
- [API Documentation](docs/api/endpoints.md) - API endpoints reference
- [Live Demo](demo/) - Next.js demo application

## 🎨 Demo Application

A complete Next.js demo application is included in the `demo/` directory:

```bash
cd demo
npm install
npm run dev
# Open http://localhost:3000
```

The demo showcases all core module features with a modern UI built with shadcn/ui and Tailwind CSS.

## 🛠️ Creating Custom Modules

Use the provided scaffolding scripts:

```bash
# Create a module with routes
cd internal/modules
./new_module_with_route.sh mymodule

# Create a module without routes (middleware only)
./new_module_with_no_route.sh mymodule
```

Each module must implement the `config.Module` interface:

```go
type Module interface {
    Name() string
    Init(ctx context.Context, deps ModuleDependencies) error
    Routes() []RouteInfo
    Models() []interface{}
    Dependencies() []string
    RegisterHooks(events EventBus) error
    Middlewares() []MiddlewareConfig
}
```

See [module documentation](internal/modules/README.md) for details.

## 🤝 Contributing

We welcome contributions! See our [Contributing Guide](.github/CONTRIBUTING.md).

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`go test ./...`)
5. Commit (`git commit -m 'Add amazing feature'`)
6. Push (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Gin](https://github.com/gin-gonic/gin) - HTTP web framework
- [Echo](https://github.com/labstack/echo) - High performance HTTP framework
- [Chi](https://github.com/go-chi/chi) - Lightweight HTTP router
- [Fiber](https://github.com/gofiber/fiber) - Express inspired web framework
- [GORM](https://gorm.io/) - ORM library for Go
- [JWT-Go](https://github.com/golang-jwt/jwt) - JWT implementation

## 📊 Project Status

- ✅ Modular architecture
- ✅ Core authentication module
- ✅ Multiple framework support
- ✅ Notification module (Email/SMS)
- ✅ Two-factor authentication
- ✅ OAuth integration
- ✅ Rate limiting
- ✅ Captcha protection
- ✅ CSRF protection
- ✅ Event-driven architecture
- ✅ Async event processing
- ✅ Swagger/OpenAPI docs
- ✅ Comprehensive testing
- 🔄 Additional OAuth providers
- 🔄 WebAuthn/Passkeys support

## 🆘 Support

- 📖 [Documentation](docs/)
- 🐛 [Bug Reports](.github/ISSUE_TEMPLATE/bug_report.md)
- 💡 [Feature Requests](.github/ISSUE_TEMPLATE/feature_request.md)
- 💬 [Discussions](https://github.com/bete7512/goauth/discussions)

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=bete7512/goauth&type=Date)](https://star-history.com/#bete7512/goauth&Date)

---

**Made with ❤️ by the GoAuth community**
