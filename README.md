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
    "net/http"

    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/types"
    "github.com/gin-gonic/gin"
)

func main() {
    // Create configuration
    config := types.Config{
        Server: types.ServerConfig{
            Type: "gin",
            Port: 8080,
        },
        Database: types.DatabaseConfig{
            Type: "sqlite",
            URL:  "file::memory:?cache=shared",
        },
        JWTSecret: "your-secret-key-32-chars-long",
        AuthConfig: types.AuthConfig{
            Cookie: types.CookieConfig{
                Name:            "auth_token",
                AccessTokenTTL:  3600,
                RefreshTokenTTL: 86400,
                Path:            "/",
                MaxAge:          86400,
            },
        },
        PasswordPolicy: types.PasswordPolicy{
            HashSaltLength: 16,
            MinLength:      8,
        },
    }

    // Initialize GoAuth
    auth, err := goauth.NewAuth(config)
    if err != nil {
        log.Fatal(err)
    }

    // Setup Gin router
    router := gin.Default()

    // Setup authentication routes
    err = auth.GetGinAuthRoutes(router)
    if err != nil {
        log.Fatal(err)
    }

    // Start server
    log.Fatal(router.Run(":8080"))
}
```

## 📖 Framework Examples

### Gin Framework

```go
package main

import (
    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/types"
    "github.com/gin-gonic/gin"
)

func main() {
    config := createConfig()
    auth, _ := goauth.NewAuth(config)
    
    router := gin.Default()
    auth.GetGinAuthRoutes(router)
    
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
    auth, _ := goauth.NewAuth(config)
    
    e := echo.New()
    auth.SetupEchoRoutes(e)
    
    e.Start(":8080")
}
```

### Chi Framework

```go
package main

import (
    "github.com/bete7512/goauth"
    "github.com/go-chi/chi/v5"
)

func main() {
    config := createConfig()
    auth, _ := goauth.NewAuth(config)
    
    r := chi.NewRouter()
    auth.SetupChiRoutes(r)
    
    http.ListenAndServe(":8080", r)
}
```

### Fiber Framework

```go
package main

import (
    "github.com/bete7512/goauth"
    "github.com/gofiber/fiber/v2"
)

func main() {
    config := createConfig()
    auth, _ := goauth.NewAuth(config)
    
    app := fiber.New()
    auth.SetupFiberRoutes(app)
    
    app.Listen(":8080")
}
```

## 🔧 Configuration

### Basic Configuration

```go
config := types.Config{
    Server: types.ServerConfig{
        Type: "gin",
        Port: 8080,
    },
    Database: types.DatabaseConfig{
        Type: "postgres",
        URL:  "postgres://user:pass@localhost/dbname",
    },
    JWTSecret: "your-secret-key-32-chars-long",
    AuthConfig: types.AuthConfig{
        Cookie: types.CookieConfig{
            Name:            "auth_token",
            AccessTokenTTL:  3600,
            RefreshTokenTTL: 86400,
            Path:            "/",
            MaxAge:          86400,
        },
        EnableTwoFactor:         true,
        EnableEmailVerification: true,
    },
    PasswordPolicy: types.PasswordPolicy{
        HashSaltLength: 16,
        MinLength:      8,
        RequireUpper:   true,
        RequireLower:   true,
        RequireNumber:  true,
        RequireSpecial: true,
    },
}
```

### OAuth Configuration

```go
config.Providers.Enabled = []types.AuthProvider{
    types.Google, types.GitHub, types.Facebook,
}
config.Providers.Google = types.ProviderConfig{
    ClientID:     "your-google-client-id",
    ClientSecret: "your-google-client-secret",
    RedirectURL:  "http://localhost:8080/oauth/google/callback",
}
```

### Advanced Features

```go
// Rate Limiting
config.EnableRateLimiter = true
config.RateLimiter = &types.RateLimiterConfig{
    DefaultConfig: types.LimiterConfig{
        WindowSize:    60,
        MaxRequests:   100,
        BlockDuration: 10,
    },
}

// reCAPTCHA
config.EnableRecaptcha = true
config.RecaptchaConfig = &types.RecaptchaConfig{
    SecretKey: "your-recaptcha-secret",
    SiteKey:   "your-recaptcha-site-key",
}

// Swagger Documentation
config.Swagger.Enable = true
config.Swagger.Title = "My API"
config.Swagger.Version = "1.0.0"
config.Swagger.DocPath = "/docs"
```

## 🔌 Available Endpoints

### Core Authentication
- `POST /register` - User registration
- `POST /login` - User login
- `POST /logout` - User logout
- `POST /refresh-token` - Refresh access token
- `POST /forgot-password` - Password reset request
- `POST /reset-password` - Password reset
- `GET /me` - Get current user profile
- `PUT /update-profile` - Update user profile
- `DELETE /deactivate-user` - Deactivate user account

### Two-Factor Authentication
- `POST /enable-two-factor` - Enable 2FA
- `POST /verify-two-factor` - Verify 2FA code
- `POST /disable-two-factor` - Disable 2FA

### Email Verification
- `POST /verify-email` - Verify email address
- `POST /resend-verification-email` - Resend verification email

### OAuth Providers
- `GET /oauth/{provider}/login` - OAuth login
- `GET /oauth/{provider}/callback` - OAuth callback

### Magic Link
- `POST /magic-link` - Send magic link
- `GET /magic-link-login` - Magic link login

## 🎣 Hooks System

GoAuth provides a flexible hook system for customizing authentication behavior:

```go
// Register before hook
auth.RegisterBeforeHook("/login", func(w http.ResponseWriter, r *http.Request) (bool, error) {
    // Custom logic before login
    return true, nil // Return false to abort the request
})

// Register after hook
auth.RegisterAfterHook("/register", func(w http.ResponseWriter, r *http.Request) (bool, error) {
    // Custom logic after registration
    return true, nil
})
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
testConfigs := goauth.GetTestConfigurations()

// Minimal config for basic tests
config := testConfigs.MinimalConfig()

// Full feature config for comprehensive tests
config := testConfigs.FullFeatureConfig()

// OAuth only config
config := testConfigs.OAuthOnlyConfig()
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