# GoAuth API Package

This package provides a unified authentication API that works with multiple popular Go web frameworks. The architecture is designed to be framework-agnostic while providing optimal integration for each supported framework.

## 🏗️ Architecture

The API package is organized into several layers:

```
api/
├── core/           # Core interfaces and handlers
│   ├── interfaces.go  # Framework-agnostic interfaces
│   └── handler.go     # Core authentication handler
├── frameworks/     # Framework-specific adapters
│   ├── gin.go         # Gin framework adapter
│   ├── chi.go         # Chi framework adapter
│   ├── echo.go        # Echo framework adapter
│   ├── fiber.go       # Fiber framework adapter
│   ├── gorilla_mux.go # Gorilla Mux adapter
│   └── standard.go    # Standard HTTP adapter
├── routes/         # Route handlers (existing)
├── middlewares/    # Middleware implementations (existing)
└── api.go         # Main API interface
```

## 🚀 Quick Start

### 1. Create Auth Service

```go
package main

import (
    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/api"
)

func main() {
    // Create your auth service
    authService, err := goauth.NewBuilder().
        WithConfig(config).
        Build()
    if err != nil {
        log.Fatal(err)
    }

    // Create the API
    authAPI := api.NewAuthAPI(authService)
}
```

### 2. Setup Routes for Your Framework

#### Gin
```go
import "github.com/gin-gonic/gin"

func setupGin(authAPI *api.AuthAPI) {
    r := gin.Default()
    
    // Setup authentication routes
    err := authAPI.SetupGinRoutes(r)
    if err != nil {
        log.Fatal(err)
    }
    
    r.Run(":8080")
}
```

#### Chi
```go
import "github.com/go-chi/chi/v5"

func setupChi(authAPI *api.AuthAPI) {
    r := chi.NewRouter()
    
    // Setup authentication routes
    err := authAPI.SetupChiRoutes(r)
    if err != nil {
        log.Fatal(err)
    }
    
    http.ListenAndServe(":8080", r)
}
```

#### Echo
```go
import "github.com/labstack/echo/v4"

func setupEcho(authAPI *api.AuthAPI) {
    e := echo.New()
    
    // Setup authentication routes
    err := authAPI.SetupEchoRoutes(e)
    if err != nil {
        log.Fatal(err)
    }
    
    e.Start(":8080")
}
```

#### Fiber
```go
import "github.com/gofiber/fiber/v2"

func setupFiber(authAPI *api.AuthAPI) {
    app := fiber.New()
    
    // Setup authentication routes
    err := authAPI.SetupFiberRoutes(app)
    if err != nil {
        log.Fatal(err)
    }
    
    app.Listen(":8080")
}
```

#### Gorilla Mux
```go
import "github.com/gorilla/mux"

func setupGorillaMux(authAPI *api.AuthAPI) {
    r := mux.NewRouter()
    
    // Setup authentication routes
    err := authAPI.SetupGorillaMuxRoutes(r)
    if err != nil {
        log.Fatal(err)
    }
    
    http.ListenAndServe(":8080", r)
}
```

#### Standard HTTP
```go
import "net/http"

func setupStandard(authAPI *api.AuthAPI) {
    mux := http.NewServeMux()
    
    // Setup authentication routes
    err := authAPI.SetupStandardRoutes(mux)
    if err != nil {
        log.Fatal(err)
    }
    
    http.ListenAndServe(":8080", mux)
}
```

## 📋 Supported Frameworks

| Framework | Package | Status | Notes |
|-----------|---------|--------|-------|
| Gin | `github.com/gin-gonic/gin` | ✅ Supported | Full integration |
| Chi | `github.com/go-chi/chi/v5` | ✅ Supported | Full integration |
| Echo | `github.com/labstack/echo/v4` | ✅ Supported | Full integration |
| Fiber | `github.com/gofiber/fiber/v2` | ✅ Supported | Full integration |
| Gorilla Mux | `github.com/gorilla/mux` | ✅ Supported | Full integration |
| Standard HTTP | `net/http` | ✅ Supported | Basic integration |

## 🔧 API Reference

### AuthAPI

The main interface for setting up authentication routes.

#### Methods

- `NewAuthAPI(auth *types.Auth) *AuthAPI` - Create a new API instance
- `SetupRoutes(frameworkType, router) error` - Setup routes for any framework
- `GetMiddleware(frameworkType) (interface{}, error)` - Get framework middleware
- `GetRoutes() []RouteDefinition` - Get all available routes
- `GetCoreRoutes() []RouteDefinition` - Get core authentication routes
- `GetOAuthRoutes() []RouteDefinition` - Get OAuth provider routes

#### Convenience Methods

- `SetupGinRoutes(router) error`
- `SetupChiRoutes(router) error`
- `SetupEchoRoutes(router) error`
- `SetupFiberRoutes(router) error`
- `SetupGorillaMuxRoutes(router) error`
- `SetupStandardRoutes(router) error`

## 🛣️ Available Routes

All frameworks register the same set of authentication routes under the configured base path:

### Core Authentication Routes

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/register` | User registration |
| `POST` | `/auth/login` | User login |
| `POST` | `/auth/logout` | User logout |
| `POST` | `/auth/refresh-token` | Token refresh |
| `POST` | `/auth/forgot-password` | Password reset request |
| `POST` | `/auth/reset-password` | Password reset |
| `POST` | `/auth/update-profile` | Profile update |
| `POST` | `/auth/deactivate-user` | User deactivation |
| `GET` | `/auth/me` | Get current user |
| `POST` | `/auth/enable-two-factor` | Enable 2FA |
| `POST` | `/auth/verify-two-factor` | Verify 2FA |
| `POST` | `/auth/disable-two-factor` | Disable 2FA |
| `POST` | `/auth/verify-email` | Email verification |
| `POST` | `/auth/resend-verification-email` | Resend verification email |
| `POST` | `/auth/send-magic-link` | Send magic link |
| `POST` | `/auth/verify-magic-login` | Verify magic link |

### OAuth Routes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/oauth/{provider}` | OAuth provider sign-in |
| `GET` | `/auth/oauth/{provider}/callback` | OAuth provider callback |

Supported OAuth providers: `google`, `github`

## 🔌 Middleware Support

Each framework adapter provides framework-specific middleware:

```go
// Get middleware for your framework
middleware, err := authAPI.GetMiddleware(api.FrameworkGin)
if err != nil {
    log.Fatal(err)
}

// Use the middleware with your framework
// (Implementation varies by framework)
```

## 🎯 Features

- **Framework Agnostic**: Single API for multiple frameworks
- **Type Safe**: Strong typing with Go interfaces
- **Middleware Support**: Framework-specific middleware
- **OAuth Integration**: Multiple OAuth provider support
- **Rate Limiting**: Built-in rate limiting support
- **Hook System**: Customizable hooks for authentication events
- **Swagger Support**: Optional API documentation
- **Error Handling**: Comprehensive error handling

## 📦 Dependencies

Add the required framework dependencies to your `go.mod`:

```bash
go get github.com/gin-gonic/gin
go get github.com/go-chi/chi/v5
go get github.com/labstack/echo/v4
go get github.com/gofiber/fiber/v2
go get github.com/gorilla/mux
```

## 🔄 Migration from Old Structure

If you're migrating from the old API structure:

### Old Way
```go
// Old structure
handler := api.NewGinHandler(authHandler)
handler.SetupRoutes(ginEngine)
```

### New Way
```go
// New structure
authAPI := api.NewAuthAPI(authService)
err := authAPI.SetupGinRoutes(ginEngine)
```

The new structure provides better organization, type safety, and a unified interface across all frameworks.

## 🤝 Contributing

To add support for a new framework:

1. Create a new adapter in `api/frameworks/`
2. Implement the `FrameworkAdapter` interface
3. Add the framework type to `core/interfaces.go`
4. Update the factory in `api/api.go`
5. Add tests and documentation

## 📄 License

This package is part of the GoAuth project and follows the same license terms. 