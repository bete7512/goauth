# Global Caching System

The go-auth library now includes a comprehensive global caching system that supports multiple cache backends and custom implementations. This system follows the same pattern as the repository system, providing a unified interface for different cache types.

## Features

- **Multiple Cache Backends**: Redis, in-memory, Valkey, and custom implementations
- **Unified Interface**: Single cache interface for all implementations
- **Factory Pattern**: Easy switching between cache types via configuration
- **High-Level Service**: CacheService provides convenient methods for common operations
- **Graceful Degradation**: Falls back to no-op cache when cache is unavailable
- **Thread-Safe**: All implementations are thread-safe
- **Custom Implementations**: Support for custom cache implementations

## Supported Cache Types

### 1. Memory Cache
Fast in-memory caching with automatic cleanup of expired items.

```go
config := config.Config{
    Cache: config.CacheConfig{
        Type:       config.MemoryCache,
        Enabled:    true,
        DefaultTTL: 5 * time.Minute,
    },
}
```

### 2. Redis Cache
Distributed caching using Redis.

```go
config := config.Config{
    Cache: config.CacheConfig{
        Type:    config.RedisCache,
        Enabled: true,
        Redis: config.RedisConfig{
            Host:     "localhost",
            Port:     6379,
            Database: 0,
            Password: "",
        },
    },
}
```

### 3. Valkey Cache
Alternative to Redis with similar functionality.

```go
config := config.Config{
    Cache: config.CacheConfig{
        Type:    config.ValkeyCache,
        Enabled: true,
        Valkey: config.ValkeyConfig{
            Host:     "localhost",
            Port:     6379,
            Database: 0,
            Password: "",
        },
    },
}
```

### 4. Custom Cache
Implement your own cache backend.

```go
type MyCustomCache struct {
    // Your implementation
}

func (c *MyCustomCache) Get(ctx context.Context, key string) (interface{}, error) {
    // Your implementation
}

// ... implement all interface methods

config := config.Config{
    Cache: config.CacheConfig{
        Type:             config.CustomCache,
        Enabled:          true,
        EnableCustomCache: true,
        CustomCache: config.CustomCacheConfig{
            Factory: &MyCustomCacheFactory{
                cache: &MyCustomCache{},
            },
        },
    },
}
```

### 5. No Cache
Disable caching entirely.

```go
config := config.Config{
    Cache: config.CacheConfig{
        Type:    config.NoCache,
        Enabled: false,
    },
}
```

## Basic Usage

### Initializing Cache

```go
import (
    "github.com/bete7512/goauth/internal/caches"
    "github.com/bete7512/goauth/internal/services"
    "github.com/bete7512/goauth/pkg/config"
)

// Create cache factory
factory, err := caches.NewCacheFactory(config)
if err != nil {
    log.Fatal("Failed to create cache factory:", err)
}

// Get cache instance
cache := factory.GetCache()

// Create cache service for high-level operations
cacheService := services.NewCacheService(cache)
```

### Basic Operations

```go
ctx := context.Background()

// Set a value
err := cacheService.Set(ctx, "key", "value", 5*time.Minute)

// Get a value
var value string
err = cacheService.Get(ctx, "key", &value)

// Check if key exists
exists, err := cacheService.Exists(ctx, "key")

// Delete a key
err = cacheService.Delete(ctx, "key")

// Increment a counter
counter, err := cacheService.Incr(ctx, "counter")

// Set expiration
success, err := cacheService.Expire(ctx, "key", 10*time.Minute)

// Get TTL
ttl, err := cacheService.TTL(ctx, "key")
```

### Advanced Patterns

#### GetOrSet Pattern
```go
var result string
err := cacheService.GetOrSet(ctx, "expensive:operation", &result, func() (interface{}, error) {
    // Expensive operation here
    return "expensive result", nil
}, 5*time.Minute)
```

#### Atomic Operations
```go
// Set only if key doesn't exist
success, err := cacheService.SetNX(ctx, "lock:resource", "locked", 1*time.Minute)
if success {
    // Lock acquired
}
```

#### User Data Caching
```go
// Cache user data
userData := map[string]interface{}{
    "id":    "user123",
    "name":  "John Doe",
    "email": "john@example.com",
}
err := cacheService.CacheUser(ctx, "user123", userData, 30*time.Minute)

// Retrieve cached user data
var cachedUser map[string]interface{}
err = cacheService.GetCachedUser(ctx, "user123", &cachedUser)

// Invalidate user cache
err = cacheService.InvalidateUserCache(ctx, "user123")
```

#### Token Caching
```go
// Cache token data
tokenData := map[string]interface{}{
    "user_id": "user123",
    "expires": time.Now().Add(time.Hour),
}
err := cacheService.CacheToken(ctx, "token123", tokenData, time.Hour)

// Retrieve cached token
var cachedToken map[string]interface{}
err = cacheService.GetCachedToken(ctx, "token123", &cachedToken)

// Invalidate token cache
err = cacheService.InvalidateTokenCache(ctx, "token123")
```

## Integration with Auth System

The cache system is integrated into the main Auth struct:

```go
type Auth struct {
    Config           *Config
    Repository       interfaces.RepositoryFactory
    HookManager      hooks.HookManager
    TokenManager     interfaces.TokenManagerInterface
    RateLimiter      interfaces.RateLimiter
    RecaptchaManager interfaces.CaptchaVerifier
    CSRFManager      interfaces.CSRFManager
    Cache            interfaces.Cache  // New cache field
    WorkerPool       pond.Pool
    Logger           logger.Log
}
```

### Using Cache in Handlers

```go
func (h *AuthHandler) HandleGetCSRFToken(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value(config.UserIDKey).(string)
    
    // Try to get from cache first
    if h.Auth.Cache != nil {
        cacheKey := "csrf:" + userID
        if cachedValue, err := h.Auth.Cache.Get(r.Context(), cacheKey); err == nil {
            if cachedToken, ok := cachedValue.(string); ok {
                // Return cached token
                utils.RespondWithJSON(w, http.StatusOK, map[string]string{
                    "message": "CSRF token retrieved from cache",
                    "token":   cachedToken,
                })
                return
            }
        }
    }
    
    // Generate new token if not in cache
    token, err := h.authService.GetCSRFToken(r.Context(), userID)
    if err != nil {
        utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), nil)
        return
    }
    
    // Cache the new token
    if h.Auth.Cache != nil {
        cacheKey := "csrf:" + userID
        h.Auth.Cache.Set(r.Context(), cacheKey, token, h.Auth.Config.Security.CSRF.TokenTTL)
    }
    
    utils.RespondWithJSON(w, http.StatusOK, map[string]string{
        "message": "CSRF token generated",
        "token":   token,
    })
}
```

## Cache Interface

All cache implementations must implement the `interfaces.Cache` interface:

```go
type Cache interface {
    Get(ctx context.Context, key string) (interface{}, error)
    Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
    Delete(ctx context.Context, key string) error
    Exists(ctx context.Context, key string) (bool, error)
    SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error)
    Incr(ctx context.Context, key string) (int64, error)
    Expire(ctx context.Context, key string, expiration time.Duration) (bool, error)
    TTL(ctx context.Context, key string) (time.Duration, error)
    Close() error
}
```

## Error Handling

The cache system defines standard error types:

```go
var (
    ErrCacheKeyNotFound = errors.New("cache key not found")
    ErrCacheKeyExpired  = errors.New("cache key expired")
    ErrCacheConnection  = errors.New("cache connection error")
)
```

## Configuration

Cache configuration is part of the main config structure:

```go
type CacheConfig struct {
    Type CacheType
    // Redis configuration (used when Type is RedisCache)
    Redis RedisConfig
    // Valkey configuration (used when Type is ValkeyCache)
    Valkey ValkeyConfig
    // Custom cache configuration
    EnableCustomCache bool
    CustomCache       CustomCacheConfig
    // Global cache settings
    DefaultTTL time.Duration
    Enabled    bool
}
```

## Best Practices

1. **Always check if cache is available**: `if h.Auth.Cache != nil`
2. **Use appropriate TTLs**: Don't cache data longer than necessary
3. **Handle cache misses gracefully**: Always have a fallback to the original data source
4. **Use atomic operations**: Use `SetNX` for locks and distributed coordination
5. **Invalidate cache when data changes**: Keep cache consistent with data source
6. **Monitor cache performance**: Track hit rates and response times
7. **Use meaningful cache keys**: Include context in key names (e.g., `user:123:profile`)

## Examples

See the `examples/cache-usage/main.go` file for comprehensive examples of using the caching system with different backends and patterns.

## Migration from Existing Code

If you're using the existing Redis client directly, you can migrate to the new cache system:

### Before
```go
redisClient := caches.NewRedisClient(config.Redis)
value, err := redisClient.Get("key")
```

### After
```go
factory, err := caches.NewCacheFactory(config)
cache := factory.GetCache()
value, err := cache.Get(ctx, "key")
```

The new system provides better abstraction, error handling, and support for multiple cache backends. 