---
id: custom-storage
title: Custom Storage
sidebar_label: Custom Storage
sidebar_position: 3
---

# Custom Storage

Learn how to implement custom storage backends for GoAuth.

## Overview

GoAuth is designed with a flexible storage architecture that allows you to implement custom storage backends for users, tokens, and sessions. This enables integration with your existing database systems or custom data stores.

## Storage Interfaces

GoAuth defines several interfaces that you can implement:

### 1. User Repository Interface

```go
type UserRepository interface {
    Create(ctx context.Context, user *models.User) error
    GetByID(ctx context.Context, id string) (*models.User, error)
    GetByEmail(ctx context.Context, email string) (*models.User, error)
    GetByPhone(ctx context.Context, phone string) (*models.User, error)
    Update(ctx context.Context, user *models.User) error
    Delete(ctx context.Context, id string) error
    List(ctx context.Context, filter *models.UserFilter) ([]*models.User, error)
}
```

### 2. Token Repository Interface

```go
type TokenRepository interface {
    Create(ctx context.Context, token *models.Token) error
    GetByID(ctx context.Context, id string) (*models.Token, error)
    GetByValue(ctx context.Context, value string) (*models.Token, error)
    Update(ctx context.Context, token *models.Token) error
    Delete(ctx context.Context, id string) error
    DeleteExpired(ctx context.Context) error
    Cleanup(ctx context.Context, userID string) error
}
```

### 3. Session Repository Interface

```go
type SessionRepository interface {
    Create(ctx context.Context, session *models.Session) error
    GetByID(ctx context.Context, id string) (*models.Session, error)
    GetByUserID(ctx context.Context, userID string) ([]*models.Session, error)
    Update(ctx context.Context, session *models.Session) error
    Delete(ctx context.Context, id string) error
    DeleteExpired(ctx context.Context) error
}
```

## Implementation Examples

### 1. Custom User Repository

```go
package custom

import (
    "context"
    "database/sql"
    "github.com/your-org/goauth/pkg/models"
    "github.com/your-org/goauth/pkg/interfaces"
)

type CustomUserRepository struct {
    db *sql.DB
}

func NewCustomUserRepository(db *sql.DB) interfaces.UserRepository {
    return &CustomUserRepository{db: db}
}

func (r *CustomUserRepository) Create(ctx context.Context, user *models.User) error {
    query := `
        INSERT INTO users (id, email, password_hash, name, phone, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `

    _, err := r.db.ExecContext(ctx, query,
        user.ID,
        user.Email,
        user.PasswordHash,
        user.Name,
        user.Phone,
        user.CreatedAt,
        user.UpdatedAt,
    )

    return err
}

func (r *CustomUserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
    query := `
        SELECT id, email, password_hash, name, phone, created_at, updated_at
        FROM users WHERE id = $1
    `

    user := &models.User{}
    err := r.db.QueryRowContext(ctx, query, id).Scan(
        &user.ID,
        &user.Email,
        &user.PasswordHash,
        &user.Name,
        &user.Phone,
        &user.CreatedAt,
        &user.UpdatedAt,
    )

    if err != nil {
        return nil, err
    }

    return user, nil
}

func (r *CustomUserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
    query := `
        SELECT id, email, password_hash, name, phone, created_at, updated_at
        FROM users WHERE email = $1
    `

    user := &models.User{}
    err := r.db.QueryRowContext(ctx, query, email).Scan(
        &user.ID,
        &user.Email,
        &user.PasswordHash,
        &user.Name,
        &user.Phone,
        &user.CreatedAt,
        &user.UpdatedAt,
    )

    if err != nil {
        return nil, err
    }

    return user, nil
}

func (r *CustomUserRepository) Update(ctx context.Context, user *models.User) error {
    query := `
        UPDATE users
        SET email = $2, password_hash = $3, name = $4, phone = $5, updated_at = $6
        WHERE id = $1
    `

    _, err := r.db.ExecContext(ctx, query,
        user.ID,
        user.Email,
        user.PasswordHash,
        user.Name,
        user.Phone,
        user.UpdatedAt,
    )

    return err
}

func (r *CustomUserRepository) Delete(ctx context.Context, id string) error {
    query := `DELETE FROM users WHERE id = $1`
    _, err := r.db.ExecContext(ctx, query, id)
    return err
}

func (r *CustomUserRepository) List(ctx context.Context, filter *models.UserFilter) ([]*models.User, error) {
    // Implement user listing with filters
    // This is a simplified example
    query := `SELECT id, email, name, created_at FROM users ORDER BY created_at DESC`

    rows, err := r.db.QueryContext(ctx, query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var users []*models.User
    for rows.Next() {
        user := &models.User{}
        err := rows.Scan(&user.ID, &user.Email, &user.Name, &user.CreatedAt)
        if err != nil {
            return nil, err
        }
        users = append(users, user)
    }

    return users, nil
}
```

### 2. Custom Token Repository

```go
package custom

import (
    "context"
    "database/sql"
    "time"
    "github.com/your-org/goauth/pkg/models"
    "github.com/your-org/goauth/pkg/interfaces"
)

type CustomTokenRepository struct {
    db *sql.DB
}

func NewCustomTokenRepository(db *sql.DB) interfaces.TokenRepository {
    return &CustomTokenRepository{db: db}
}

func (r *CustomTokenRepository) Create(ctx context.Context, token *models.Token) error {
    query := `
        INSERT INTO tokens (id, user_id, type, value, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
    `

    _, err := r.db.ExecContext(ctx, query,
        token.ID,
        token.UserID,
        token.Type,
        token.Value,
        token.ExpiresAt,
        token.CreatedAt,
    )

    return err
}

func (r *CustomTokenRepository) GetByValue(ctx context.Context, value string) (*models.Token, error) {
    query := `
        SELECT id, user_id, type, value, expires_at, created_at
        FROM tokens WHERE value = $1
    `

    token := &models.Token{}
    err := r.db.QueryRowContext(ctx, query, value).Scan(
        &token.ID,
        &token.UserID,
        &token.Type,
        &token.Value,
        &token.ExpiresAt,
        &token.CreatedAt,
    )

    if err != nil {
        return nil, err
    }

    return token, nil
}

func (r *CustomTokenRepository) DeleteExpired(ctx context.Context) error {
    query := `DELETE FROM tokens WHERE expires_at < $1`
    _, err := r.db.ExecContext(ctx, query, time.Now())
    return err
}

func (r *CustomTokenRepository) Cleanup(ctx context.Context, userID string) error {
    query := `DELETE FROM tokens WHERE user_id = $1`
    _, err := r.db.ExecContext(ctx, query, userID)
    return err
}
```

### 3. Custom Session Repository

```go
package custom

import (
    "context"
    "database/sql"
    "time"
    "github.com/your-org/goauth/pkg/models"
    "github.com/your-org/goauth/pkg/interfaces"
)

type CustomSessionRepository struct {
    db *sql.DB
}

func NewCustomSessionRepository(db *sql.DB) interfaces.SessionRepository {
    return &CustomSessionRepository{db: db}
}

func (r *CustomSessionRepository) Create(ctx context.Context, session *models.Session) error {
    query := `
        INSERT INTO sessions (id, user_id, token, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5)
    `

    _, err := r.db.ExecContext(ctx, query,
        session.ID,
        session.UserID,
        session.Token,
        session.ExpiresAt,
        session.CreatedAt,
    )

    return err
}

func (r *CustomSessionRepository) GetByID(ctx context.Context, id string) (*models.Session, error) {
    query := `
        SELECT id, user_id, token, expires_at, created_at
        FROM sessions WHERE id = $1
    `

    session := &models.Session{}
    err := r.db.QueryRowContext(ctx, query, id).Scan(
        &session.ID,
        &session.UserID,
        &session.Token,
        &session.ExpiresAt,
        &session.CreatedAt,
    )

    if err != nil {
        return nil, err
    }

    return session, nil
}

func (r *CustomSessionRepository) DeleteExpired(ctx context.Context) error {
    query := `DELETE FROM sessions WHERE expires_at < $1`
    _, err := r.db.ExecContext(ctx, query, time.Now())
    return err
}
```

## Database Schema

### Users Table

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    email_verified BOOLEAN DEFAULT FALSE,
    phone_verified BOOLEAN DEFAULT FALSE,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_phone ON users(phone);
```

### Tokens Table

```sql
CREATE TABLE tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_tokens_user_id ON tokens(user_id);
CREATE INDEX idx_tokens_value ON tokens(value);
CREATE INDEX idx_tokens_expires_at ON tokens(expires_at);
```

### Sessions Table

```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(token);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
```

## Integration with GoAuth

### 1. Factory Pattern

```go
package custom

import (
    "github.com/your-org/goauth/pkg/interfaces"
    "github.com/your-org/goauth/pkg/repositories"
)

type CustomRepositoryFactory struct {
    userRepo    interfaces.UserRepository
    tokenRepo   interfaces.TokenRepository
    sessionRepo interfaces.SessionRepository
}

func NewCustomRepositoryFactory(db *sql.DB) repositories.RepositoryFactory {
    return &CustomRepositoryFactory{
        userRepo:    NewCustomUserRepository(db),
        tokenRepo:   NewCustomTokenRepository(db),
        sessionRepo: NewCustomSessionRepository(db),
    }
}

func (f *CustomRepositoryFactory) GetUserRepository() interfaces.UserRepository {
    return f.userRepo
}

func (f *CustomRepositoryFactory) GetTokenRepository() interfaces.TokenRepository {
    return f.tokenRepo
}

func (f *CustomRepositoryFactory) GetSessionRepository() interfaces.SessionRepository {
    return f.sessionRepo
}
```

### 2. Configuration

```go
cfg := &config.Config{
    Storage: config.StorageConfig{
        Type: "custom",
        Custom: config.CustomStorageConfig{
            Factory: NewCustomRepositoryFactory(db),
        },
    },
}
```

## Testing Custom Storage

### 1. Unit Tests

```go
package custom

import (
    "testing"
    "context"
    "github.com/stretchr/testify/assert"
    "github.com/your-org/goauth/pkg/models"
)

func TestCustomUserRepository_Create(t *testing.T) {
    // Setup test database
    db := setupTestDB(t)
    defer db.Close()

    repo := NewCustomUserRepository(db)

    user := &models.User{
        ID:           "test-id",
        Email:        "test@example.com",
        PasswordHash: "hashed-password",
        Name:         "Test User",
    }

    err := repo.Create(context.Background(), user)
    assert.NoError(t, err)

    // Verify user was created
    retrieved, err := repo.GetByID(context.Background(), user.ID)
    assert.NoError(t, err)
    assert.Equal(t, user.Email, retrieved.Email)
}
```

### 2. Integration Tests

```go
func TestCustomStorageIntegration(t *testing.T) {
    // Setup test database
    db := setupTestDB(t)
    defer db.Close()

    // Create repository factory
    factory := NewCustomRepositoryFactory(db)

    // Initialize GoAuth with custom storage
    cfg := &config.Config{
        Storage: config.StorageConfig{
            Type: "custom",
            Custom: config.CustomStorageConfig{
                Factory: factory,
            },
        },
    }

    auth, err := goauth.New(cfg)
    assert.NoError(t, err)

    // Test authentication flow
    // ... test implementation
}
```

## Performance Considerations

### 1. Connection Pooling

```go
import (
    "github.com/jackc/pgx/v4/pgxpool"
)

func NewCustomUserRepository(pool *pgxpool.Pool) interfaces.UserRepository {
    return &CustomUserRepository{pool: pool}
}
```

### 2. Caching

```go
type CachedUserRepository struct {
    cache interfaces.Cache
    repo  interfaces.UserRepository
}

func (r *CachedUserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
    // Try cache first
    if cached, err := r.cache.Get("user:" + id); err == nil {
        return cached.(*models.User), nil
    }

    // Fallback to database
    user, err := r.repo.GetByID(ctx, id)
    if err != nil {
        return nil, err
    }

    // Cache for future requests
    r.cache.Set("user:"+id, user, time.Hour)

    return user, nil
}
```

## Next Steps

- [Security Features](../features/security.md) - Learn about advanced security features
- [Configuration](../configuration/auth.md) - Customize your storage configuration
- [API Reference](../api/endpoints.md) - Explore the complete API
- [Examples](../examples/basic-auth.md) - See complete implementation examples
