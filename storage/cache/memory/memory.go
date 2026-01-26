package memory

import (
	"context"
	"sync"
	"time"

	"github.com/bete7512/goauth/pkg/types"
)

// Compile-time check
var _ types.Cache = (*MemoryCache)(nil)

// cacheEntry holds a cached value with expiration
type cacheEntry struct {
	value     []byte
	expiresAt time.Time
}

// MemoryCache is a simple in-memory cache implementation
// Suitable for single-instance deployments or testing
// For distributed systems, use Redis or similar
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	done    chan struct{}
}

// NewMemoryCache creates a new in-memory cache
// cleanupInterval specifies how often to remove expired entries
func NewMemoryCache(cleanupInterval time.Duration) *MemoryCache {
	c := &MemoryCache{
		entries: make(map[string]cacheEntry),
		done:    make(chan struct{}),
	}

	// Start cleanup goroutine
	go c.cleanup(cleanupInterval)

	return c
}

func (c *MemoryCache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false, nil
	}

	// Check expiration
	if time.Now().After(entry.expiresAt) {
		return nil, false, nil
	}

	return entry.value, true, nil
}

func (c *MemoryCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (c *MemoryCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, key)
	return nil
}

func (c *MemoryCache) DeletePattern(ctx context.Context, pattern string) error {
	// Simple pattern matching - only supports prefix patterns like "user:*"
	// For more complex patterns, consider using a proper glob library
	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove trailing *
	prefix := pattern
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix = pattern[:len(pattern)-1]
	}

	for key := range c.entries {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(c.entries, key)
		}
	}
	return nil
}

func (c *MemoryCache) Close() error {
	close(c.done)
	return nil
}

// cleanup periodically removes expired entries
func (c *MemoryCache) cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.removeExpired()
		case <-c.done:
			return
		}
	}
}

func (c *MemoryCache) removeExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}
