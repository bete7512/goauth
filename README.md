# GoAuth 🔐

[![Go Report Card](https://goreportcard.com/badge/github.com/bete7512/goauth)](https://goreportcard.com/report/github.com/bete7512/goauth)
[![Go Version](https://img.shields.io/github/go-mod/go-version/bete7512/goauth)](https://go.dev/)
[![License](https://img.shields.io/github/license/bete7512/goauth)](LICENSE)
[![Release](https://img.shields.io/github/v/release/bete7512/goauth)](https://github.com/bete7512/goauth/releases)
[![CI/CD](https://img.shields.io/github/actions/workflow/status/bete7512/goauth/ci.yml?branch=main)](https://github.com/bete7512/goauth/actions)
[![Coverage](https://img.shields.io/codecov/c/github/bete7512/goauth)](https://codecov.io/gh/bete7512/goauth)

A comprehensive, framework-agnostic authentication library for Go applications. GoAuth provides a unified authentication system that works seamlessly across multiple web frameworks including Gin, Echo, Chi, Fiber, and standard HTTP.

## ✨ Features

- 🔐 **Multi-Framework Support**: Works with Gin, Echo, Chi, Fiber, Gorilla Mux, and standard HTTP
- 🔑 **JWT Authentication**: Secure token-based authentication with customizable claims
- 🔒 **OAuth Integration**: Support for Google, GitHub, Facebook, Microsoft, Apple, Discord, and more
- 🛡️ **Security Features**: Rate limiting, reCAPTCHA, two-factor authentication, email verification
- 🗄️ **Database Agnostic**: Support for PostgreSQL, MySQL, MongoDB, and SQLite
- 🎣 **Hook System**: Customizable before/after hooks for authentication events
- 📊 **Comprehensive Logging**: Built-in logging with customizable levels
- 🧪 **Extensive Testing**: Unit tests, integration tests, and benchmarks
- 📚 **Auto-Generated Docs**: Swagger/OpenAPI documentation
- 🚀 **Production Ready**: Battle-tested with comprehensive error handling
- 🔧 **Builder Pattern**: Flexible configuration with builder pattern
- 🎯 **HTTP-First Design**: Clean HTTP-only implementation

## 🚀 Quick Start

### Installation

```bash
go get github.com/bete7512/goauth
```

### Basic Usage

```go
package main

import (
    "log"
    "time"

    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/config"
    "github.com/gin-gonic/gin"
)

func main() {
    // Create configuration
    config := config.Config{
        App: config.AppConfig{
            BasePath:    "/auth",
            Domain:      "localhost",
            FrontendURL: "http://localhost:3000",
        },
        Database: config.DatabaseConfig{
            Type: "postgres",
            URL:  "postgres://user:pass@localhost/dbname?sslmode=disable",
        },
        AuthConfig: config.AuthConfig{
            JWT: config.JWTConfig{
                Secret:             "your-secret-key-32-chars-long",
                AccessTokenTTL:     15 * time.Minute,
                RefreshTokenTTL:    7 * 24 * time.Hour,
                EnableCustomClaims: false,
            },
            Tokens: config.TokenConfig{
                HashSaltLength:       16,
                PhoneVerificationTTL: 10 * time.Minute,
                EmailVerificationTTL: 1 * time.Hour,
                PasswordResetTTL:     10 * time.Minute,
                TwoFactorTTL:         10 * time.Minute,
                MagicLinkTTL:         10 * time.Minute,
            },
            Methods: config.AuthMethodsConfig{
                Type:                  config.AuthenticationTypeEmail,
                EnableTwoFactor:       true,
                EnableMultiSession:    false,
                EnableMagicLink:       false,
                EnableSmsVerification: false,
                TwoFactorMethod:       "email",
                EmailVerification: config.EmailVerificationConfig{
                    EnableOnSignup:   true,
                    VerificationURL:  "http://localhost:3000/verify",
                    SendWelcomeEmail: false,
                },
            },
            PasswordPolicy: config.PasswordPolicy{
                HashSaltLength: 16,
                MinLength:      8,
                RequireUpper:   true,
                RequireLower:   true,
                RequireNumber:  true,
                RequireSpecial: true,
            },
            Cookie: config.CookieConfig{
                Name:     "auth_token",
                Path:     "/",
                MaxAge:   86400,
                Secure:   false,
                HttpOnly: true,
                SameSite: 1,
            },
        },
        Features: config.FeaturesConfig{
            EnableRateLimiter:   false,
            EnableRecaptcha:     false,
            EnableCustomJWT:     false,
            EnableCustomStorage: false,
        },
        Security: config.SecurityConfig{
            RateLimiter: config.RateLimiterConfig{
                Enabled: false,
                Type:    config.MemoryRateLimiter,
                Routes:  make(map[string]config.LimiterConfig),
            },
            Recaptcha: config.RecaptchaConfig{
                Enabled:   false,
                SecretKey: "",
                SiteKey:   "",
                Provider:  "google",
                APIURL:    "",
                Routes:    make(map[string]bool),
            },
        },
        Email: config.EmailConfig{
            Sender: config.EmailSenderConfig{
                Type:         "sendgrid",
                FromEmail:    "noreply@example.com",
                FromName:     "My App",
                SupportEmail: "support@example.com",
                CustomSender: nil,
            },
        },
        SMS: config.SMSConfig{
            CompanyName:  "My App",
            CustomSender: nil,
        },
        Providers: config.ProvidersConfig{
            Enabled: []config.AuthProvider{},
        },
    }

    // Initialize GoAuth using the builder pattern
    auth, err := goauth.NewBuilder().WithConfig(config).Build()
    if err != nil {
        log.Fatal(err)
    }

    // Setup Gin router
    router := gin.Default()

    // Register auth routes manually
    authRoutes := auth.GetRoutes()
    for _, route := range authRoutes {
        handler := auth.GetWrappedHandler(route)
        ginHandler := gin.WrapF(handler)
        
        switch route.Method {
        case "GET":
            router.GET(route.Path, ginHandler)
        case "POST":
            router.POST(route.Path, ginHandler)
        case "PUT":
            router.PUT(route.Path, ginHandler)
        case "DELETE":
            router.DELETE(route.Path, ginHandler)
        }
    }
    
    router.Run(":8080")
}
```

## 📖 Framework Examples

### Gin Framework

```go
package main

import (
    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/config"
    "github.com/gin-gonic/gin"
)

func main() {
    config := createConfig()
    auth, _ := goauth.NewBuilder().WithConfig(config).Build()
    
    router := gin.Default()
    
    // Register auth routes manually
    authRoutes := auth.GetRoutes()
    for _, route := range authRoutes {
        handler := auth.GetWrappedHandler(route)
        ginHandler := gin.WrapF(handler)
        
        switch route.Method {
        case "GET":
            router.GET(route.Path, ginHandler)
        case "POST":
            router.POST(route.Path, ginHandler)
        case "PUT":
            router.PUT(route.Path, ginHandler)
        case "DELETE":
            router.DELETE(route.Path, ginHandler)
        }
    }
    
    router.Run(":8080")
}
```

### Echo Framework

```go
package main

import (
    "github.com/bete7512/goauth"
    "github.com/labstack/echo/v4"
)

func main() {
    config := createConfig()
    auth, _ := goauth.NewBuilder().WithConfig(config).Build()
    
    e := echo.New()
    
    // Register auth routes manually
    authRoutes := auth.GetRoutes()
    for _, route := range authRoutes {
        handler := auth.GetWrappedHandler(route)
        e.Any(route.Path, echo.WrapHandler(http.HandlerFunc(handler)))
    }
    
    e.Start(":8080")
}
```

### Chi Framework

```go
package main

import (
    "github.com/bete7512/goauth"
    "github.com/go-chi/chi/v5"
    "net/http"
)

func main() {
    config := createConfig()
    auth, _ := goauth.NewBuilder().WithConfig(config).Build()
    
    r := chi.NewRouter()
    
    // Register auth routes manually
    authRoutes := auth.GetRoutes()
    for _, route := range authRoutes {
        handler := auth.GetWrappedHandler(route)
        r.HandleFunc(route.Method+" "+route.Path, handler)
    }
    
    http.ListenAndServe(":8080", r)
}
```

### Fiber Framework

```go
package main

import (
    "github.com/bete7512/goauth"
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/adaptor"
)

func main() {
    config := createConfig()
    auth, _ := goauth.NewBuilder().WithConfig(config).Build()
    
    app := fiber.New()
    
    // Register auth routes manually
    authRoutes := auth.GetRoutes()
    for _, route := range authRoutes {
        handler := auth.GetWrappedHandler(route)
        fiberHandler := adaptor.HTTPHandler(http.HandlerFunc(handler))
        
        switch route.Method {
        case "GET":
            app.Get(route.Path, fiberHandler)
        case "POST":
            app.Post(route.Path, fiberHandler)
        case "PUT":
            app.Put(route.Path, fiberHandler)
        case "DELETE":
            app.Delete(route.Path, fiberHandler)
        }
    }
    
    app.Listen(":8080")
}
```

### Standard HTTP

```go
package main

import (
    "github.com/bete7512/goauth"
    "net/http"
)

func main() {
    config := createConfig()
    auth, _ := goauth.NewBuilder().WithConfig(config).Build()
    
    mux := http.NewServeMux()
    
    // Register auth routes manually
    authRoutes := auth.GetRoutes()
    for _, route := range authRoutes {
        handler := auth.GetWrappedHandler(route)
        mux.HandleFunc(route.Method+" "+route.Path, handler)
    }
    
    http.ListenAndServe(":8080", mux)
}
```

## 🔧 Configuration

### Basic Configuration

```go
config := config.Config{
    App: config.AppConfig{
        BasePath:    "/auth",
        Domain:      "localhost",
        FrontendURL: "http://localhost:3000",
    },
    Database: config.DatabaseConfig{
        Type: "postgres",
        URL:  "postgres://user:pass@localhost/dbname?sslmode=disable",
    },
    AuthConfig: config.AuthConfig{
        JWT: config.JWTConfig{
            Secret:             "your-secret-key-32-chars-long",
            AccessTokenTTL:     15 * time.Minute,
            RefreshTokenTTL:    7 * 24 * time.Hour,
            EnableCustomClaims: false,
        },
        Tokens: config.TokenConfig{
            HashSaltLength:       16,
            PhoneVerificationTTL: 10 * time.Minute,
            EmailVerificationTTL: 1 * time.Hour,
            PasswordResetTTL:     10 * time.Minute,
            TwoFactorTTL:         10 * time.Minute,
            MagicLinkTTL:         10 * time.Minute,
        },
        Methods: config.AuthMethodsConfig{
            Type:                  config.AuthenticationTypeEmail,
            EnableTwoFactor:       true,
            EnableMultiSession:    false,
            EnableMagicLink:       false,
            EnableSmsVerification: false,
            TwoFactorMethod:       "email",
            EmailVerification: config.EmailVerificationConfig{
                EnableOnSignup:   true,
                VerificationURL:  "http://localhost:3000/verify",
                SendWelcomeEmail: false,
            },
        },
        PasswordPolicy: config.PasswordPolicy{
            HashSaltLength: 16,
            MinLength:      8,
            RequireUpper:   true,
            RequireLower:   true,
            RequireNumber:  true,
            RequireSpecial: true,
        },
        Cookie: config.CookieConfig{
            Name:     "auth_token",
            Path:     "/",
            MaxAge:   86400,
            Secure:   false,
            HttpOnly: true,
            SameSite: 1,
        },
    },
    Features: config.FeaturesConfig{
        EnableRateLimiter:   true,
        EnableRecaptcha:     true,
        EnableCustomJWT:     false,
        EnableCustomStorage: false,
    },
}
```

### OAuth Configuration

```go
config.Providers.Enabled = []config.AuthProvider{
    config.Google, config.GitHub, config.Facebook,
}
config.Providers.Google = config.ProviderConfig{
    ClientID:     "your-google-client-id",
    ClientSecret: "your-google-client-secret",
    RedirectURL:  "http://localhost:8080/auth/oauth/google/callback",
    Scopes:       []string{"email", "profile"},
}
```

### Advanced Features

```go
// Rate Limiting
config.Features.EnableRateLimiter = true
config.Security.RateLimiter = config.RateLimiterConfig{
    Enabled: true,
    Type:    config.MemoryRateLimiter,
    Routes: map[string]config.LimiterConfig{
        config.RouteRegister: {
            WindowSize:    30 * time.Second,
            MaxRequests:   10,
            BlockDuration: 1 * time.Minute,
        },
        config.RouteLogin: {
            WindowSize:    1 * time.Minute,
            MaxRequests:   5,
            BlockDuration: 1 * time.Minute,
        },
    },
}

// reCAPTCHA
config.Features.EnableRecaptcha = true
config.Security.Recaptcha = config.RecaptchaConfig{
    Enabled:   true,
    Provider:  "google",
    SecretKey: "your-recaptcha-secret",
    SiteKey:   "your-recaptcha-site-key",
    APIURL:    "https://www.google.com/recaptcha/api/siteverify",
    Routes: map[string]bool{
        config.RouteRegister: true,
        config.RouteLogin:    true,
    },
}

// Swagger Documentation
config.App.Swagger = config.SwaggerConfig{
    Enable:      true,
    Title:       "My API",
    Version:     "1.0.0",
    DocPath:     "/docs",
    Description: "API Documentation",
    Host:        "localhost:8080",
}
```

### Custom JWT Claims

```go
type ClaimsProvider struct{}

func (c *ClaimsProvider) GetClaims(user models.User) (map[string]interface{}, error) {
    return map[string]interface{}{
        "tenants":           []string{"one", "two"},
        "primary_tenant_id": "2534532",
    }, nil
}

config.AuthConfig.JWT.EnableCustomClaims = true
config.AuthConfig.JWT.ClaimsProvider = &ClaimsProvider{}
```

### Custom Storage Repository

```go
// Create custom repository factory
customFactory := &MyRepositoryFactory{}

// Use builder with custom repository
auth, err := goauth.NewBuilder().
    WithConfig(config).
    WithRepositoryFactory(customFactory).
    Build()
```

### Custom Captcha Verifier

```go
// Create custom captcha verifier
customCaptcha := &MyCaptchaVerifier{}

// Use builder with custom captcha
auth, err := goauth.NewBuilder().
    WithConfig(config).
    WithCaptchaVerifier(customCaptcha).
    Build()
```

## 🔌 Available Endpoints

### Core Authentication
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `POST /auth/refresh-token` - Refresh access token
- `POST /auth/forgot-password` - Password reset request
- `POST /auth/reset-password` - Password reset
- `GET /auth/me` - Get current user profile
- `POST /auth/update-profile` - Update user profile
- `POST /auth/deactivate-user` - Deactivate user account

### Two-Factor Authentication
- `POST /auth/enable-two-factor` - Enable 2FA
- `POST /auth/verify-two-factor` - Verify 2FA code
- `POST /auth/disable-two-factor` - Disable 2FA

### Email Verification
- `POST /auth/verification/email/send` - Send verification email
- `POST /auth/verification/email/verify` - Verify email address

### Phone Verification
- `POST /auth/verification/phone/send` - Send verification SMS
- `POST /auth/verification/phone/verify` - Verify phone number

### OAuth Providers
- `GET /auth/oauth/{provider}` - OAuth login
- `GET /auth/oauth/{provider}/callback` - OAuth callback

### Magic Link
- `POST /auth/send-magic-link` - Send magic link
- `POST /auth/verify-magic-link` - Magic link login

## 🎣 Hooks System

GoAuth provides a flexible hook system for customizing authentication behavior:

```go
// Register before hook
err := auth.RegisterBeforeHook(config.RouteRegister, func(w http.ResponseWriter, r *http.Request) (bool, error) {
    // Custom logic before registration
    log.Println("Before registration hook executing...")
    return true, nil // Return false to abort the request
})

// Register after hook
err = auth.RegisterAfterHook(config.RouteLogin, func(w http.ResponseWriter, r *http.Request) (bool, error) {
    // Custom logic after login
    log.Println("After login hook executing...")
    
    // Access request and response data from context
    reqData := r.Context().Value(config.RequestDataKey)
    respData := r.Context().Value(config.ResponseDataKey)
    
    log.Printf("Request data: %+v\n", reqData)
    log.Printf("Response data: %+v\n", respData)
    
    return true, nil
})
```

## 🔧 Middleware Usage

### Authentication Middleware

```go
// Get authentication middleware
authMiddleware := auth.GetAuthMiddleware()

// Apply to your routes
protectedHandler := authMiddleware(yourHandler)
```

### Rate Limiting Middleware

```go
// Get rate limiting middleware for specific route
rateLimitMiddleware := auth.GetRateLimitMiddleware("login")

// Apply to your routes
rateLimitedHandler := rateLimitMiddleware(yourHandler)
```

### Manual Route Registration

```go
// Get all routes for manual registration
routes := auth.GetRoutes()

// Register routes manually with your framework
for _, route := range routes {
    // Apply middleware if needed
    handler := auth.GetWrappedHandler(route)
    
    // Register with your router
    router.HandleFunc(route.Method+" "+route.Path, handler)
}
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
make test-all

# Run unit tests only
make test

# Run integration tests
make test-integration

# Run benchmarks
make test-benchmark

# Generate coverage report
make test-coverage
```

### Test Configuration

```go
// Use test configurations for different scenarios
func createTestConfig() config.Config {
    return config.Config{
        App: config.AppConfig{
            BasePath:    "/auth",
            Domain:      "localhost",
            FrontendURL: "http://localhost:3000",
        },
        Database: config.DatabaseConfig{
            Type: "postgres",
            URL:  "postgres://test:test@localhost:5432/test",
        },
        AuthConfig: config.AuthConfig{
            JWT: config.JWTConfig{
                Secret:             "test-secret-key",
                AccessTokenTTL:     15 * time.Minute,
                RefreshTokenTTL:    7 * 24 * time.Hour,
                EnableCustomClaims: false,
            },
            Tokens: config.TokenConfig{
                HashSaltLength:       16,
                PhoneVerificationTTL: 10 * time.Minute,
                EmailVerificationTTL: 1 * time.Hour,
                PasswordResetTTL:     10 * time.Minute,
                TwoFactorTTL:         10 * time.Minute,
                MagicLinkTTL:         10 * time.Minute,
            },
            Methods: config.AuthMethodsConfig{
                Type:                  config.AuthenticationTypeEmail,
                EnableTwoFactor:       false,
                EnableMultiSession:    false,
                EnableMagicLink:       false,
                EnableSmsVerification: false,
            },
            PasswordPolicy: config.PasswordPolicy{
                HashSaltLength: 16,
                MinLength:      8,
                RequireUpper:   true,
                RequireLower:   true,
                RequireNumber:  true,
                RequireSpecial: false,
            },
            Cookie: config.CookieConfig{
                Name:     "auth_token",
                Path:     "/",
                MaxAge:   86400,
                Secure:   false,
                HttpOnly: true,
                SameSite: 1,
            },
        },
        Features: config.FeaturesConfig{
            EnableRateLimiter:   false,
            EnableRecaptcha:     false,
            EnableCustomJWT:     false,
            EnableCustomStorage: false,
        },
        Security: config.SecurityConfig{
            RateLimiter: config.RateLimiterConfig{
                Enabled: false,
                Type:    config.MemoryRateLimiter,
                Routes:  make(map[string]config.LimiterConfig),
            },
            Recaptcha: config.RecaptchaConfig{
                Enabled:   false,
                SecretKey: "",
                SiteKey:   "",
                Provider:  "google",
                APIURL:    "",
                Routes:    make(map[string]bool),
            },
        },
        Email: config.EmailConfig{
            Sender: config.EmailSenderConfig{
                Type:         "sendgrid",
                FromEmail:    "test@example.com",
                FromName:     "Test App",
                SupportEmail: "support@example.com",
                CustomSender: nil,
            },
        },
        SMS: config.SMSConfig{
            CompanyName:  "Test Company",
            CustomSender: nil,
        },
        Providers: config.ProvidersConfig{
            Enabled: []config.AuthProvider{},
        },
    }
}
```

## 📚 Documentation

- [API Documentation](docs/api/README.md) - Detailed API reference
- [Framework Integration](docs/frameworks/README.md) - Framework-specific guides
- [Configuration Guide](docs/configuration/README.md) - Configuration options
- [Security Best Practices](docs/security/README.md) - Security recommendations

## 🛠️ Development

### Prerequisites

- Go 1.21 or later
- Git
- Make (optional)

### Setup

```bash
# Clone the repository
git clone https://github.com/bete7512/goauth.git
cd goauth

# Install development tools
make install-tools

# Download dependencies
make deps

# Run tests
make test-all
```

### Code Quality

```bash
# Format code
make fmt

# Run linter
make lint

# Run security scanner
make security

# Run all quality checks
make quality
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](.github/CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test-all`)
5. Check code quality (`make quality`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Gin](https://github.com/gin-gonic/gin) - HTTP web framework
- [Echo](https://github.com/labstack/echo) - High performance HTTP framework
- [Chi](https://github.com/go-chi/chi) - Lightweight HTTP router
- [Fiber](https://github.com/gofiber/fiber) - Express inspired web framework
- [GORM](https://gorm.io/) - ORM library for Go
- [JWT-Go](https://github.com/golang-jwt/jwt) - JWT implementation

## 📊 Project Status

- ✅ Core authentication features
- ✅ Multi-framework support
- ✅ OAuth integration
- ✅ Security features
- ✅ Comprehensive testing
- ✅ Documentation
- ✅ Builder pattern implementation
- ✅ HTTP-first design
- 🔄 Performance optimizations
- 🔄 Additional OAuth providers

## 🆘 Support

- 📖 [Documentation](docs/)
- 🐛 [Bug Reports](.github/ISSUE_TEMPLATE/bug_report.md)
- 💡 [Feature Requests](.github/ISSUE_TEMPLATE/feature_request.md)
- 💬 [Discussions](https://github.com/bete7512/goauth/discussions)

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=bete7512/goauth&type=Date)](https://star-history.com/#bete7512/goauth&Date)

---

**Made with ❤️ by the GoAuth community**

## 🔧 Integration Approach

GoAuth uses manual route registration to provide full control over how routes are integrated with web frameworks. This approach allows you to:

- Apply framework-specific middleware to individual routes
- Customize route handling per endpoint
- Better debugging and logging
- More granular control over HTTP methods

```go
// Get all auth routes
authRoutes := auth.GetRoutes()

// Register each route individually
for _, route := range authRoutes {
    handler := auth.GetWrappedHandler(route)
    
    // Apply framework-specific conversion
    frameworkHandler := convertToFrameworkHandler(handler)
    
    // Register with your framework
    registerRoute(route.Method, route.Path, frameworkHandler)
}
```

## 📚 Framework Examples 