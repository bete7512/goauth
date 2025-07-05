package memory

import (
	"context"
	"sync"
	"time"

	"github.com/bete7512/goauth/pkg/interfaces"
)

type cacheItem struct {
	Value      interface{}
	Expiration time.Time
}

type MemoryCache struct {
	data  map[string]cacheItem
	mutex sync.RWMutex
	ttl   time.Duration
}

type MemoryCacheFactory struct {
	cache *MemoryCache
}

// NewCacheFactory creates a new memory cache factory
func NewCacheFactory(defaultTTL time.Duration) interfaces.CacheFactory {
	return &MemoryCacheFactory{
		cache: &MemoryCache{
			data: make(map[string]cacheItem),
			ttl:  defaultTTL,
		},
	}
}

// // NewNoOpCacheFactory creates a no-op cache factory for when caching is disabled
// func NewNoOpCacheFactory() interfaces.CacheFactory {
// 	return &MemoryCacheFactory{
// 		cache: &MemoryCache{
// 			data: make(map[string]cacheItem),
// 			ttl:  0, // No TTL for no-op cache
// 		},
// 	}
// }

func (f *MemoryCacheFactory) GetCache() interfaces.Cache {
	return f.cache
}

func (c *MemoryCache) Get(ctx context.Context, key string) (interface{}, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	item, exists := c.data[key]
	if !exists {
		return nil, interfaces.ErrCacheKeyNotFound
	}

	// Check if item is expired
	if !item.Expiration.IsZero() && time.Now().After(item.Expiration) {
		// Remove expired item
		c.mutex.RUnlock()
		c.mutex.Lock()
		delete(c.data, key)
		c.mutex.Unlock()
		c.mutex.RLock()
		return nil, interfaces.ErrCacheKeyNotFound
	}

	return item.Value, nil
}

func (c *MemoryCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	var exp time.Time
	if expiration > 0 {
		exp = time.Now().Add(expiration)
	} else if c.ttl > 0 {
		exp = time.Now().Add(c.ttl)
	}

	c.data[key] = cacheItem{
		Value:      value,
		Expiration: exp,
	}

	return nil
}

func (c *MemoryCache) Delete(ctx context.Context, key string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.data, key)
	return nil
}

func (c *MemoryCache) Exists(ctx context.Context, key string) (bool, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	item, exists := c.data[key]
	if !exists {
		return false, nil
	}

	// Check if item is expired
	if !item.Expiration.IsZero() && time.Now().After(item.Expiration) {
		// Remove expired item
		c.mutex.RUnlock()
		c.mutex.Lock()
		delete(c.data, key)
		c.mutex.Unlock()
		c.mutex.RLock()
		return false, nil
	}

	return true, nil
}

func (c *MemoryCache) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if key already exists
	if _, exists := c.data[key]; exists {
		return false, nil
	}

	var exp time.Time
	if expiration > 0 {
		exp = time.Now().Add(expiration)
	} else if c.ttl > 0 {
		exp = time.Now().Add(c.ttl)
	}

	c.data[key] = cacheItem{
		Value:      value,
		Expiration: exp,
	}

	return true, nil
}

func (c *MemoryCache) Incr(ctx context.Context, key string) (int64, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	item, exists := c.data[key]
	if !exists {
		// Create new counter
		c.data[key] = cacheItem{
			Value:      int64(1),
			Expiration: time.Now().Add(c.ttl),
		}
		return 1, nil
	}

	// Check if item is expired
	if !item.Expiration.IsZero() && time.Now().After(item.Expiration) {
		c.data[key] = cacheItem{
			Value:      int64(1),
			Expiration: time.Now().Add(c.ttl),
		}
		return 1, nil
	}

	// Increment existing counter
	if counter, ok := item.Value.(int64); ok {
		counter++
		c.data[key] = cacheItem{
			Value:      counter,
			Expiration: item.Expiration,
		}
		return counter, nil
	}

	// If value is not a counter, start from 1
	c.data[key] = cacheItem{
		Value:      int64(1),
		Expiration: item.Expiration,
	}
	return 1, nil
}

func (c *MemoryCache) Expire(ctx context.Context, key string, expiration time.Duration) (bool, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	item, exists := c.data[key]
	if !exists {
		return false, nil
	}

	// Check if item is expired
	if !item.Expiration.IsZero() && time.Now().After(item.Expiration) {
		delete(c.data, key)
		return false, nil
	}

	// Update expiration
	c.data[key] = cacheItem{
		Value:      item.Value,
		Expiration: time.Now().Add(expiration),
	}

	return true, nil
}

func (c *MemoryCache) TTL(ctx context.Context, key string) (time.Duration, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	item, exists := c.data[key]
	if !exists {
		return -1, nil // Key doesn't exist
	}

	// Check if item is expired
	if !item.Expiration.IsZero() && time.Now().After(item.Expiration) {
		return -2, nil // Key exists but has no expiration
	}

	if item.Expiration.IsZero() {
		return -2, nil // Key exists but has no expiration
	}

	return time.Until(item.Expiration), nil
}

func (c *MemoryCache) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Clear all data
	c.data = make(map[string]cacheItem)
	return nil
}

// Cleanup removes expired items from the cache
func (c *MemoryCache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	for key, item := range c.data {
		if !item.Expiration.IsZero() && now.After(item.Expiration) {
			delete(c.data, key)
		}
	}
}
