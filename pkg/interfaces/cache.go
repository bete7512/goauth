package interfaces

import (
	"context"
	"errors"
	"time"
)

// Cache error constants
var (
	ErrCacheKeyNotFound = errors.New("cache key not found")
	ErrCacheKeyExpired  = errors.New("cache key expired")
	ErrCacheConnection  = errors.New("cache connection error")
)

// Cache interface defines the basic caching operations
type Cache interface {
	// Get retrieves a value from cache
	Get(ctx context.Context, key string) (interface{}, error)

	// Set stores a value in cache with optional expiration
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error

	// Delete removes a key from cache
	Delete(ctx context.Context, key string) error

	// Exists checks if a key exists in cache
	Exists(ctx context.Context, key string) (bool, error)

	// SetNX sets a value if the key doesn't exist (atomic operation)
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error)

	// Incr increments a key's value (for counters)
	Incr(ctx context.Context, key string) (int64, error)

	// Expire sets an expiration time on a key
	Expire(ctx context.Context, key string, expiration time.Duration) (bool, error)

	// TTL gets the remaining time to live for a key
	TTL(ctx context.Context, key string) (time.Duration, error)

	// Close closes the cache connection
	Close() error
}

// CacheFactory interface defines the factory for creating cache instances
type CacheFactory interface {
	// GetCache returns the cache instance
	GetCache() Cache
}

// CacheType represents different types of cache implementations
type CacheType string

const (
	RedisCache  CacheType = "redis"
	MemoryCache CacheType = "memory"
	ValkeyCache CacheType = "valkey"
	CustomCache CacheType = "custom"
	NoCache     CacheType = "none"
)
