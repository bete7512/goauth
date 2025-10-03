# Storage Architecture Guide

## Overview

The storage layer follows a **clean architecture** pattern with clear separation of concerns:

- **`pkg/storage/`** - Public interfaces and types (no internal dependencies)
- **`internal/modules/{module}/models/`** - Each module defines its repository interfaces
- **`internal/storage/{dialect}/modules/{module}/`** - Concrete implementations per storage backend
- **`internal/storage/storage.go`** - Repository name constants and contracts

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      pkg/storage/                            │
│  ┌────────────────────────────────────────────────────┐     │
│  │ Storage Interface (dialect-agnostic)                │     │
│  │ - Initialize(), Close(), Migrate()                  │     │
│  │ - GetRepository(name) interface{}                   │     │
│  │ - BeginTx() Transaction                             │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                           ▲
                           │ implements
                           │
┌──────────────────────────┴──────────────────────────────────┐
│            internal/storage/{gorm|mongo|sqlc}/               │
│  ┌────────────────────────────────────────────────────┐     │
│  │ GormStorage / MongoStorage / SqlcStorage           │     │
│  │ - Registers all module repositories                 │     │
│  │ - repositories map[string]interface{}               │     │
│  └────────────────────────────────────────────────────┘     │
│                           │                                   │
│         ┌─────────────────┼─────────────────┐               │
│         ▼                 ▼                 ▼                │
│   modules/core/     modules/admin/    modules/oauth/         │
│   - user.go         - auditlog.go     - provider.go          │
└─────────────────────────────────────────────────────────────┘
                           ▲
                           │ implements interface from
                           │
┌──────────────────────────┴──────────────────────────────────┐
│        internal/modules/{module}/models/                     │
│  ┌────────────────────────────────────────────────────┐     │
│  │ UserRepository interface                            │     │
│  │ SessionRepository interface                         │     │
│  │ AuditLogRepository interface                        │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## Key Principles

### 1. **Repository Interface Per Module**

Each module defines its repository interface in `internal/modules/{module}/models/`:

```go
// internal/modules/core/models/user.go
package models

type User struct {
    ID       string
    Email    string
    Password string
}

type UserRepository interface {
    Create(ctx context.Context, user *User) error
    FindByEmail(ctx context.Context, email string) (*User, error)
    FindByID(ctx context.Context, id string) (*User, error)
    Update(ctx context.Context, user *User) error
    Delete(ctx context.Context, id string) error
}
```

### 2. **Repository Implementation Per Storage Backend**

Each storage backend implements the repository interface:

```go
// internal/storage/gorm/modules/core/user.go
package core

import "gorm.io/gorm"

type UserRepository struct {
    db *gorm.DB
}

var _ models.UserRepository = (*UserRepository)(nil)

func NewUserRepository(db *gorm.DB) *UserRepository {
    return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
    return r.db.WithContext(ctx).Create(user).Error
}
// ... implement other methods
```

### 3. **Repository Registration**

Storage backends register repositories with string keys:

```go
// internal/storage/storage.go
const (
    CoreUserRepository    = "core.user"
    CoreSessionRepository = "core.session"
    AdminAuditLogRepository = "admin.auditlog"
)

// internal/storage/gorm/gorm.go
func (s *GormStorage) registerRepositories() {
    s.repositories[storage.CoreUserRepository] = core.NewUserRepository(s.db)
    s.repositories[storage.CoreSessionRepository] = core.NewSessionRepository(s.db)
    s.repositories[storage.AdminAuditLogRepository] = admin.NewAuditLogRepository(s.db)
}
```

### 4. **Type-Safe Repository Access**

Use generic helpers for type-safe repository retrieval:

```go
// In your service/handler
userRepo, err := pkgStorage.GetTypedRepository[models.UserRepository](
    storage, 
    storage.CoreUserRepository,
)
if err != nil {
    return err
}

user, err := userRepo.FindByEmail(ctx, "user@example.com")
```

## Usage Examples

### Example 1: Using Supported Storage (GORM + PostgreSQL)

```go
package main

import (
    "context"
    _ "github.com/bete7512/goauth/internal/storage/gorm" // Register gorm storage
    "github.com/bete7512/goauth/pkg/storage"
)

func main() {
    // Configure storage
    config := storage.StorageConfig{
        Driver:      "gorm",
        Dialect:     "postgres",
        DSN:         "host=localhost user=postgres password=secret dbname=authdb",
        AutoMigrate: true,
        MaxOpenConns: 25,
        MaxIdleConns: 5,
        LogLevel:    "info",
    }

    // Create storage instance
    store, err := storage.NewStorage(config)
    if err != nil {
        panic(err)
    }
    defer store.Close()

    // Initialize
    ctx := context.Background()
    if err := store.Initialize(ctx); err != nil {
        panic(err)
    }

    // Access repository
    userRepo, err := storage.GetTypedRepository[models.UserRepository](
        store,
        storage.CoreUserRepository,
    )
    if err != nil {
        panic(err)
    }

    // Use repository
    user := &models.User{
        Email:    "test@example.com",
        Password: "hashed_password",
    }
    err = userRepo.Create(ctx, user)
}
```

### Example 2: Using Custom Storage

```go
package main

import (
    "context"
    "github.com/bete7512/goauth/internal/modules/core/models"
    "github.com/bete7512/goauth/pkg/storage"
)

// Step 1: Implement the repository interface
type MyCustomUserRepository struct {
    // Your custom database connection
    client *MyDBClient
}

func (r *MyCustomUserRepository) Create(ctx context.Context, user *models.User) error {
    // Your custom implementation
    return r.client.Insert("users", user)
}

func (r *MyCustomUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
    // Your custom implementation
    var user models.User
    err := r.client.QueryOne("users", map[string]interface{}{"email": email}, &user)
    return &user, err
}

// Implement other methods...

// Step 2: Implement the Storage interface
type MyCustomStorage struct {
    client       *MyDBClient
    repositories map[string]interface{}
}

func NewMyCustomStorage(dsn string) (*MyCustomStorage, error) {
    client, err := ConnectToMyDB(dsn)
    if err != nil {
        return nil, err
    }

    s := &MyCustomStorage{
        client:       client,
        repositories: make(map[string]interface{}),
    }

    // Register your repositories
    s.repositories[storage.CoreUserRepository] = &MyCustomUserRepository{client: client}
    s.repositories[storage.CoreSessionRepository] = &MyCustomSessionRepository{client: client}
    
    return s, nil
}

func (s *MyCustomStorage) Initialize(ctx context.Context) error {
    return s.client.Ping(ctx)
}

func (s *MyCustomStorage) Close() error {
    return s.client.Close()
}

func (s *MyCustomStorage) GetRepository(name string) interface{} {
    return s.repositories[name]
}

// Implement other methods...

// Step 3: Use your custom storage
func main() {
    customStore, err := NewMyCustomStorage("my-custom-dsn")
    if err != nil {
        panic(err)
    }

    config := storage.StorageConfig{
        Driver:        "custom",
        CustomStorage: customStore,
    }

    store, err := storage.NewStorage(config)
    // Use normally...
}
```

### Example 3: Partial Custom Repositories (Override Only Specific Repos)

```go
package main

func main() {
    // Use GORM for most repositories, but override user repository
    customUserRepo := &MyCustomUserRepository{/* ... */}

    config := storage.StorageConfig{
        Driver:   "gorm",
        Dialect:  "postgres",
        DSN:      "postgres://...",
        CustomRepositories: map[string]interface{}{
            storage.CoreUserRepository: customUserRepo, // Override only this one
        },
    }

    store, err := storage.NewStorage(config)
    // Now user repository uses your custom implementation,
    // but all other repositories use GORM
}
```

### Example 4: Using Transactions

```go
func TransferUserData(ctx context.Context, store storage.Storage) error {
    // Begin transaction
    tx, err := store.BeginTx(ctx)
    if err != nil {
        return err
    }
    defer tx.Rollback() // Rollback if not committed

    // Get repositories within transaction
    userRepo, err := storage.GetTypedRepositoryFromTx[models.UserRepository](
        tx,
        storage.CoreUserRepository,
    )
    if err != nil {
        return err
    }

    sessionRepo, err := storage.GetTypedRepositoryFromTx[models.SessionRepository](
        tx,
        storage.CoreSessionRepository,
    )
    if err != nil {
        return err
    }

    // Perform operations
    user := &models.User{Email: "test@example.com"}
    if err := userRepo.Create(ctx, user); err != nil {
        return err
    }

    session := &models.Session{UserID: user.ID, Token: "token"}
    if err := sessionRepo.Create(ctx, session); err != nil {
        return err
    }

    // Commit transaction
    return tx.Commit()
}
```

## Adding a New Module with Storage

### Step 1: Define Models and Repository Interface

```go
// internal/modules/newmodule/models/models.go
package models

type CustomEntity struct {
    ID   string
    Data string
}

type CustomEntityRepository interface {
    Create(ctx context.Context, entity *CustomEntity) error
    FindByID(ctx context.Context, id string) (*CustomEntity, error)
}
```

### Step 2: Add Repository Constant

```go
// internal/storage/storage.go
const (
    // ... existing constants
    NewModuleCustomEntityRepository = "newmodule.customentity"
)

func SupportedRepositories() []string {
    return []string{
        // ... existing
        NewModuleCustomEntityRepository,
    }
}
```

### Step 3: Implement Repository for Each Storage Backend

```go
// internal/storage/gorm/modules/newmodule/customentity.go
package newmodule

import "gorm.io/gorm"

type CustomEntityRepository struct {
    db *gorm.DB
}

var _ models.CustomEntityRepository = (*CustomEntityRepository)(nil)

func NewCustomEntityRepository(db *gorm.DB) *CustomEntityRepository {
    return &CustomEntityRepository{db: db}
}

func (r *CustomEntityRepository) Create(ctx context.Context, entity *models.CustomEntity) error {
    return r.db.WithContext(ctx).Create(entity).Error
}
// ... implement other methods
```

### Step 4: Register in Storage Implementation

```go
// internal/storage/gorm/gorm.go
import "github.com/bete7512/goauth/internal/storage/gorm/modules/newmodule"

func (s *GormStorage) registerRepositories(customRepos map[string]interface{}) {
    // ... existing registrations
    s.repositories[storage.NewModuleCustomEntityRepository] = newmodule.NewCustomEntityRepository(s.db)
}
```

## Benefits of This Architecture

✅ **Separation of Concerns**: pkg/ has no internal dependencies
✅ **Scalable**: Easy to add new modules without modifying core storage interfaces
✅ **Flexible**: Users can provide custom implementations for any/all repositories
✅ **Type-Safe**: Repository interfaces are strongly typed per module
✅ **Testable**: Easy to mock repositories for testing
✅ **Multiple Storage Backends**: Support GORM, MongoDB, SQLC, or custom backends
✅ **Transaction Support**: Built-in transaction support for all repositories

## What You Might Have Missed

### 1. **Transaction Repository Creation**
Each storage must create fresh repository instances for transactions:

```go
func (s *GormStorage) createTransactionRepositories(tx *gorm.DB) map[string]interface{} {
    repos := make(map[string]interface{})
    repos[storage.CoreUserRepository] = core.NewUserRepository(tx)
    // Use the transaction context, not the main DB
    return repos
}
```

### 2. **Repository Interface Verification**
Always verify that your implementation satisfies the interface:

```go
var _ models.UserRepository = (*UserRepository)(nil)
```

### 3. **Init Function for Registration**
Use `init()` to auto-register storage backends:

```go
func init() {
    pkgStorage.RegisterGormStorage(NewFromConfig)
}
```

### 4. **Generic Type Helpers**
Use the provided generic helpers for type-safe access:

```go
// Good
userRepo, err := storage.GetTypedRepository[models.UserRepository](store, storage.CoreUserRepository)

// Bad - requires manual type assertion
repo := store.GetRepository(storage.CoreUserRepository)
userRepo := repo.(models.UserRepository) // Can panic!
```

### 5. **Module Models Export**
Each module's `Models()` method should return migration models:

```go
func (m *CoreModule) Models() []interface{} {
    return []interface{}{
        &models.User{},
        &models.Session{},
    }
}
```

## Migration Strategy

Storage backends should support auto-migration via the `Migrate()` method:

```go
// Collect all models from modules
var allModels []interface{}
for _, module := range modules {
    allModels = append(allModels, module.Models()...)
}

// Run migration
if config.AutoMigrate {
    if err := storage.Migrate(ctx, allModels); err != nil {
        return err
    }
}
```

## Conclusion

This architecture provides a clean, scalable way to:
- Support multiple storage backends
- Allow custom implementations
- Maintain type safety
- Keep clear separation between public and internal code
- Make testing straightforward
- Enable easy addition of new modules

