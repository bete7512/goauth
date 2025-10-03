# Cross-Module Repository Access Guide

## Overview

This guide explains the best practices for accessing repositories from other modules in the go-auth architecture.

## Problem

The **Admin Module** needs to access the **User Repository** from the **Core Module** to manage users.

## Solution: 3 Approaches

### Approach 1: Type-Safe Helper Function (RECOMMENDED) ✅

**When to use:** Always prefer this approach for production code.

**Benefits:**
- Type-safe at compile time
- Clear error handling
- Follows existing architecture patterns
- Easy to test and mock

**Implementation:**

```go
// In admin/module.go Init() method
func (m *AdminModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
    m.deps = deps

    // Get User repository from core module using type-safe helper
    userRepo, err := config.GetTypedRepository[coreModels.UserRepository](
        deps.Storage,
        string(config.CoreUserRepository),
    )
    if err != nil {
        return err
    }

    // Pass to service
    adminService := services.NewAdminService(deps, auditLogRepo, userRepo)
    return nil
}
```

**How it works:**
1. Uses generic helper function `GetTypedRepository[T]` from `pkg/config/storage.go`
2. Accesses repository through `deps.Storage.GetRepository(name)`
3. Type-asserts to the expected interface
4. Returns typed repository or error

---

### Approach 2: Direct Access via Repositories Map

**When to use:** When you need more control or custom logic.

**Benefits:**
- Direct access to repositories
- Flexibility for custom implementations
- Good for optional dependencies

**Implementation:**

```go
// In admin/module.go Init() method
func (m *AdminModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
    m.deps = deps

    // Direct access from repositories map
    userRepoInterface := deps.Storage.GetRepository(string(config.CoreUserRepository))
    if userRepoInterface == nil {
        return fmt.Errorf("user repository not found")
    }

    // Type assertion
    userRepo, ok := userRepoInterface.(coreModels.UserRepository)
    if !ok {
        return fmt.Errorf("invalid user repository type")
    }

    // Pass to service
    adminService := services.NewAdminService(deps, auditLogRepo, userRepo)
    return nil
}
```

---

### Approach 3: Dependency Injection via Module Config

**When to use:** For testing, custom implementations, or when you want to decouple from storage.

**Benefits:**
- Best for testing (easy to mock)
- Supports custom implementations
- Explicit dependencies
- No dependency on storage implementation

**Implementation:**

```go
// Module configuration with optional repository injection
type Config struct {
    AuditLogRepository models.AuditLogRepository
    UserRepository     coreModels.UserRepository // Optional injection
}

func (m *AdminModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
    m.deps = deps

    // Use injected repository if provided, otherwise get from storage
    var userRepo coreModels.UserRepository
    if m.config.UserRepository != nil {
        // Use injected (e.g., for testing)
        userRepo = m.config.UserRepository
    } else {
        // Fall back to storage
        var err error
        userRepo, err = config.GetTypedRepository[coreModels.UserRepository](
            deps.Storage,
            string(config.CoreUserRepository),
        )
        if err != nil {
            return err
        }
    }

    adminService := services.NewAdminService(deps, auditLogRepo, userRepo)
    return nil
}

// Usage in production
adminModule := admin.New(&admin.Config{
    // Storage will provide default implementations
})

// Usage in tests
adminModule := admin.New(&admin.Config{
    UserRepository: mockUserRepo, // Inject mock
    AuditLogRepository: mockAuditRepo,
})
```

---

## Complete Example: Admin Module

### 1. Module Definition (admin/module.go)

```go
package admin

import (
    "context"
    "github.com/bete7512/goauth/internal/modules/admin/models"
    coreModels "github.com/bete7512/goauth/internal/modules/core/models"
    "github.com/bete7512/goauth/pkg/config"
)

type AdminModule struct {
    deps     config.ModuleDependencies
    handlers *handlers.AdminHandler
    config   *Config
}

type Config struct {
    AuditLogRepository models.AuditLogRepository
    UserRepository     coreModels.UserRepository // Cross-module dependency
}

func New(cfg *Config) *AdminModule {
    if cfg == nil {
        cfg = &Config{}
    }
    return &AdminModule{config: cfg}
}

func (m *AdminModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
    m.deps = deps

    // Get repositories (with fallback to storage)
    auditLogRepo := m.getAuditLogRepository(deps)
    userRepo := m.getUserRepository(deps)

    // Initialize services
    adminService := services.NewAdminService(deps, auditLogRepo, userRepo)
    m.handlers = handlers.NewAdminHandler(deps, adminService)

    return nil
}

func (m *AdminModule) getUserRepository(deps config.ModuleDependencies) coreModels.UserRepository {
    if m.config.UserRepository != nil {
        return m.config.UserRepository
    }

    repo, err := config.GetTypedRepository[coreModels.UserRepository](
        deps.Storage,
        string(config.CoreUserRepository),
    )
    if err != nil {
        panic(err) // Or handle gracefully
    }
    return repo
}

func (m *AdminModule) Dependencies() []string {
    return []string{string(config.CoreModule)} // Explicit dependency
}
```

### 2. Service Layer (admin/services/service.go)

```go
package services

import (
    "context"
    "github.com/bete7512/goauth/internal/modules/admin/models"
    coreModels "github.com/bete7512/goauth/internal/modules/core/models"
)

type AdminService struct {
    auditLogRepo   models.AuditLogRepository
    userRepository coreModels.UserRepository // Cross-module repository
}

func NewAdminService(
    deps config.ModuleDependencies,
    auditLogRepo models.AuditLogRepository,
    userRepo coreModels.UserRepository,
) *AdminService {
    return &AdminService{
        auditLogRepo:   auditLogRepo,
        userRepository: userRepo,
    }
}

// Use the user repository
func (s *AdminService) ListUsers(ctx context.Context, limit, offset int) ([]*coreModels.User, error) {
    return s.userRepository.List(ctx, limit, offset)
}
```

---

## Repository Name Constants

All repository names are defined in `pkg/config/constants.go`:

```go
const (
    // Core module repositories
    CoreUserRepository    RepositoryName = "core.user"
    CoreSessionRepository RepositoryName = "core.session"
    CoreTokenRepository   RepositoryName = "core.token"

    // Admin module repositories
    AdminAuditLogRepository RepositoryName = "admin.auditlog"
)
```

---

## Usage Example

```go
package main

import (
    "context"
    "github.com/bete7512/goauth/internal/modules/admin"
    "github.com/bete7512/goauth/internal/modules/core"
    "github.com/bete7512/goauth/internal/storage"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
)

func main() {
    // Create storage
    store, _ := storage.NewStorage(config.StorageConfig{
        Driver:  "gorm",
        Dialect: "sqlite",
        DSN:     "./auth.db",
    })

    // Create auth instance
    authInstance, _ := auth.New(&config.Config{
        Storage:   store,
        SecretKey: "secret",
    })

    // Register modules
    authInstance.Use(core.New(&core.Config{}))     // Core must be registered first
    authInstance.Use(admin.New(&admin.Config{}))   // Admin depends on core

    // Initialize
    authInstance.Initialize(context.Background())
}
```

---

## Testing with Mocks

```go
package admin_test

import (
    "testing"
    "github.com/bete7512/goauth/internal/modules/admin"
    coreModels "github.com/bete7512/goauth/internal/modules/core/models"
)

// Mock UserRepository
type mockUserRepository struct{}

func (m *mockUserRepository) Create(ctx context.Context, user *coreModels.User) error {
    return nil
}
func (m *mockUserRepository) FindByID(ctx context.Context, id string) (*coreModels.User, error) {
    return &coreModels.User{ID: id, Email: "test@example.com"}, nil
}
// ... implement other methods

func TestAdminModule(t *testing.T) {
    // Inject mock repository
    adminModule := admin.New(&admin.Config{
        UserRepository: &mockUserRepository{},
    })

    // Test without needing real database
}
```

---

## Best Practices

1. **Always declare dependencies** in `Dependencies()` method
2. **Use type-safe constants** from `pkg/config/constants.go`
3. **Prefer Approach 1** (GetTypedRepository) for production code
4. **Use Approach 3** (DI) for testing
5. **Handle errors gracefully** when accessing repositories
6. **Import repository interfaces only**, not implementations
7. **Keep storage implementations in `internal/storage`** directory

---

## Anti-Patterns to Avoid ❌

### ❌ Don't access other module's internal implementations

```go
// BAD - tight coupling to storage implementation
import "github.com/bete7512/goauth/internal/storage/gorm/modules/core"
userRepo := core.NewUserRepository(db)
```

### ❌ Don't bypass the repository registry

```go
// BAD - direct database access
db := deps.Storage.DB().(*gorm.DB)
db.Find(&users)
```

### ❌ Don't use untyped repository access without validation

```go
// BAD - no type safety
repo := deps.Storage.GetRepository("core.user")
users := repo.List() // What if repo is nil or wrong type?
```

---

## Summary

| Approach | Type Safety | Testability | Flexibility | Recommended For |
|----------|-------------|-------------|-------------|-----------------|
| GetTypedRepository | ✅ High | ⭐ Medium | ⭐ Medium | **Production** |
| Direct Map Access | ⭐ Medium | ⭐ Medium | ✅ High | Custom Logic |
| Dependency Injection | ✅ High | ✅ High | ✅ High | **Testing** |

**Recommendation:** Use **Approach 1** (GetTypedRepository) by default, with **Approach 3** (DI) as a fallback for testing.


