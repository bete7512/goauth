# Go-Auth Architecture Documentation

## Overview

Go-Auth is a modular authentication library for Go that provides a flexible, extensible architecture for building authentication systems. The library is designed around the concept of modules, allowing developers to pick and choose features they need.

## Core Concepts

### 1. Modular Architecture

The library is built on a modular system where each feature is encapsulated in its own module:

- **Core Module**: Basic email/password authentication (always enabled)
- **Two-Factor Module**: TOTP/SMS-based 2FA
- **OAuth Module**: Social login (Google, GitHub, etc.)
- **Magic Link Module**: Passwordless email authentication
- **Admin Module**: Administrative user management
- **CSRF Module**: Cross-site request forgery protection
- **Rate Limiter Module**: Request rate limiting

### 2. Storage Layer

The storage layer uses a repository pattern with support for multiple database backends:

```
pkg/storage/
├── storage.go          # Core storage interfaces
├── gorm/
│   ├── gorm.go        # GORM implementation
│   └── repository.go  # Repository implementations
└── custom/            # Custom storage implementations
```

#### Storage Interface

```go
type Storage interface {
    Initialize(ctx context.Context) error
    Close() error
    Migrate(ctx context.Context, models []interface{}) error
    BeginTx(ctx context.Context) (Transaction, error)
    DB() interface{}
    UserRepository() UserRepository
    SessionRepository() SessionRepository
    Repository(model interface{}) Repository
}
```

#### Features:
- **Multiple DB Support**: PostgreSQL, MySQL, SQLite
- **Transaction Support**: Built-in transaction handling
- **Repository Pattern**: Clean separation of data access logic
- **Custom Implementations**: Easy to implement custom storage backends

### 3. Event System

The event system provides a powerful hooks mechanism for extending functionality:

```
pkg/events/
├── events.go      # Event bus implementation
└── adapter.go     # Event adapters
```

#### Features:
- **Priority-based Handlers**: Execute handlers in specific order
- **Async Support**: Run handlers asynchronously
- **Event Types**: Pre-defined events for all auth operations
- **Type-safe**: Strongly typed event system

#### Event Types:
- `before:signup`, `after:signup`
- `before:login`, `after:login`
- `before:logout`, `after:logout`
- `session:created`, `session:expired`
- `password:changed`, `password:reset`
- `2fa:enabled`, `2fa:verified`
- `email:verified`

#### Usage:
```go
eventBus.Subscribe(events.EventAfterSignup, func(ctx context.Context, event *events.Event) error {
    // Send welcome email
    return sendWelcomeEmail(event.User)
}, events.WithPriority(10), events.WithAsync())
```

### 4. Middleware System

A flexible middleware system that allows modules to register middlewares with fine-grained control:

```
pkg/middleware/
├── middleware.go  # Middleware manager
└── adapter.go     # Middleware adapters
```

#### Features:
- **Route-specific**: Apply middleware to specific routes by name
- **Global Middlewares**: Apply to all routes
- **Priority-based**: Control middleware execution order
- **Pattern Matching**: Use wildcards to match route names
- **Exclusions**: Exclude specific routes from middleware

#### Configuration:
```go
type MiddlewareConfig struct {
    Name        string
    Middleware  func(http.Handler) http.Handler
    Priority    int
    ApplyTo     []string  // Route names or patterns: ["core.*", "admin.users.*"]
    ExcludeFrom []string  // Exclude patterns: ["core.login", "core.signup"]
    Global      bool      // Apply to all routes
}
```

### 5. Migration System

Automatic database migration support:

```go
config := &config.Config{
    AutoMigrate: true,
    Storage:     storage,
}
```

#### Features:
- **Auto-migration**: Automatically create/update tables
- **Model Collection**: Collects models from all modules
- **SQL Generation**: Generate SQL migration scripts
- **Version Control**: Track migration versions

### 6. Module System

Each module implements the `Module` interface:

```go
type Module interface {
    Name() string
    Init(ctx context.Context, deps ModuleDependencies) error
    Routes() []RouteInfo
    Middlewares() []MiddlewareConfig
    Models() []interface{}
    RegisterHooks(events EventBus) error
    Dependencies() []string
}
```

#### Module Dependencies:
```go
type ModuleDependencies struct {
    Storage           Storage
    Config            *Config
    Logger            Logger
    Events            EventBus
    MiddlewareManager MiddlewareManager
}
```

### 7. Route Naming

All routes have unique names for easy identification and middleware application:

```go
routes := []RouteInfo{
    {
        Name:    "core.signup",
        Path:    "/signup",
        Method:  "POST",
        Handler: h.Signup,
    },
    {
        Name:    "core.login",
        Path:    "/login",
        Method:  "POST",
        Handler: h.Login,
    },
}
```

## Usage Example

```go
package main

import (
    "context"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/storage"
    gormstorage "github.com/bete7512/goauth/pkg/storage/gorm"
    "github.com/bete7512/goauth/modules/twofactor"
    "github.com/bete7512/goauth/modules/ratelimiter"
)

func main() {
    // Create storage
    storage, err := gormstorage.New(&storage.StorageConfig{
        Driver: "postgres",
        DSN:    "postgresql://user:pass@localhost/authdb",
        MaxOpenConns: 25,
        MaxIdleConns: 5,
    })
    if err != nil {
        panic(err)
    }

    // Create auth instance
    auth, err := auth.New(&config.Config{
        Storage:         storage,
        SecretKey:       "your-secret-key",
        SessionDuration: 24 * time.Hour,
        BasePath:        "/auth",
        AutoMigrate:     true,
        CORS: &config.CORSConfig{
            Enabled:        true,
            AllowedOrigins: []string{"http://localhost:3000"},
            AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
        },
    })
    if err != nil {
        panic(err)
    }

    // Register additional modules
    auth.Use(twofactor.New())
    auth.Use(ratelimiter.New())

    // Initialize
    if err := auth.Initialize(context.Background()); err != nil {
        panic(err)
    }

    // Get routes
    routes := auth.Routes()

    // Use with your HTTP server
    // ...
}
```

## Best Practices

1. **Module Registration**: Register all modules before calling `Initialize()`
2. **Error Handling**: Always check errors from `Initialize()` and `Use()`
3. **Storage**: Initialize storage before passing to config
4. **Migrations**: Use `AutoMigrate: true` in development, manual migrations in production
5. **Events**: Use async events for non-critical operations (emails, notifications)
6. **Middlewares**: Use route patterns for applying middlewares to groups of routes
7. **Dependencies**: Ensure module dependencies are registered before dependent modules

## Creating Custom Modules

```go
type MyModule struct {
    deps config.ModuleDependencies
}

func (m *MyModule) Name() string {
    return "mymodule"
}

func (m *MyModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
    m.deps = deps
    return nil
}

func (m *MyModule) Routes() []config.RouteInfo {
    return []config.RouteInfo{
        {
            Name:    "mymodule.action",
            Path:    "/action",
            Method:  "POST",
            Handler: m.handleAction,
        },
    }
}

func (m *MyModule) Middlewares() []config.MiddlewareConfig {
    return []config.MiddlewareConfig{
        {
            Name:       "mymodule.check",
            Middleware: m.checkMiddleware,
            Priority:   50,
            ApplyTo:    []string{"mymodule.*"},
        },
    }
}

func (m *MyModule) Models() []interface{} {
    return []interface{}{&MyModel{}}
}

func (m *MyModule) RegisterHooks(events config.EventBus) error {
    // Register event handlers
    return nil
}

func (m *MyModule) Dependencies() []string {
    return []string{"core"} // Depends on core module
}
```

## Testing

Each module should include comprehensive tests:

```go
func TestModule(t *testing.T) {
    // Setup test storage
    storage := setupTestStorage(t)
    
    // Create auth with test config
    auth := setupTestAuth(t, storage)
    
    // Test module functionality
    // ...
}
```

## Future Enhancements

1. **WebAuthn Support**: Passkey/biometric authentication
2. **Session Management**: Advanced session control
3. **Audit Logging**: Comprehensive audit trails
4. **Multi-tenancy**: Support for multiple tenants
5. **Redis Support**: Redis-based session storage
6. **MongoDB Support**: MongoDB storage backend 