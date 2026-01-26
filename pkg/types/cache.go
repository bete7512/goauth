package types

import (
	"context"
	"time"
)

// Cache defines the interface for cache backends
// Implementations: Redis, Memcached, In-memory, etc.
type Cache interface {
	// Get retrieves a value from cache
	// Returns the value, whether it was found, and any error
	Get(ctx context.Context, key string) ([]byte, bool, error)

	// Set stores a value in cache with TTL
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes a value from cache
	Delete(ctx context.Context, key string) error

	// DeletePattern removes all values matching a pattern (e.g., "user:*")
	// Optional - implementations can return nil if not supported
	DeletePattern(ctx context.Context, pattern string) error

	// Close closes the cache connection
	Close() error
}
