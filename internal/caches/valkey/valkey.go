package valkey

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/redis/go-redis/v9"
)

type ValkeyCache struct {
	client *redis.Client
	ctx    context.Context
}

type ValkeyCacheFactory struct {
	cache *ValkeyCache
}

// NewCacheFactory creates a new Valkey cache factory
func NewCacheFactory(valkeyConfig config.ValkeyConfig) interfaces.CacheFactory {
	// Convert port to string properly
	portStr := strconv.Itoa(valkeyConfig.Port)

	client := redis.NewClient(&redis.Options{
		Addr:     valkeyConfig.Host + ":" + portStr,
		Password: valkeyConfig.Password,
		DB:       valkeyConfig.Database,
	})

	// Test connection
	if err := client.Ping(context.Background()).Err(); err != nil {
		log.Printf("Failed to connect to Valkey: %v", err)
		// Return a no-op cache if Valkey connection fails
		return &ValkeyCacheFactory{
			cache: &ValkeyCache{
				client: nil,
				ctx:    context.Background(),
			},
		}
	}

	return &ValkeyCacheFactory{
		cache: &ValkeyCache{
			client: client,
			ctx:    context.Background(),
		},
	}
}

func (f *ValkeyCacheFactory) GetCache() interfaces.Cache {
	return f.cache
}

func (c *ValkeyCache) Get(ctx context.Context, key string) (interface{}, error) {
	if c.client == nil {
		return nil, interfaces.ErrCacheConnection
	}

	value, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, interfaces.ErrCacheKeyNotFound
		}
		return nil, err
	}

	return value, nil
}

func (c *ValkeyCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	if c.client == nil {
		return interfaces.ErrCacheConnection
	}

	return c.client.Set(ctx, key, value, expiration).Err()
}

func (c *ValkeyCache) Delete(ctx context.Context, key string) error {
	if c.client == nil {
		return interfaces.ErrCacheConnection
	}

	return c.client.Del(ctx, key).Err()
}

func (c *ValkeyCache) Exists(ctx context.Context, key string) (bool, error) {
	if c.client == nil {
		return false, interfaces.ErrCacheConnection
	}

	result, err := c.client.Exists(ctx, key).Result()
	return result > 0, err
}

func (c *ValkeyCache) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	if c.client == nil {
		return false, interfaces.ErrCacheConnection
	}

	return c.client.SetNX(ctx, key, value, expiration).Result()
}

func (c *ValkeyCache) Incr(ctx context.Context, key string) (int64, error) {
	if c.client == nil {
		return 0, interfaces.ErrCacheConnection
	}

	return c.client.Incr(ctx, key).Result()
}

func (c *ValkeyCache) Expire(ctx context.Context, key string, expiration time.Duration) (bool, error) {
	if c.client == nil {
		return false, interfaces.ErrCacheConnection
	}

	return c.client.Expire(ctx, key, expiration).Result()
}

func (c *ValkeyCache) TTL(ctx context.Context, key string) (time.Duration, error) {
	if c.client == nil {
		return 0, interfaces.ErrCacheConnection
	}

	// Get TTL from Valkey
	ttl, err := c.client.TTL(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return -1, nil // Key doesn't exist
		}
		return 0, err
	}

	return ttl, nil
}

func (c *ValkeyCache) Close() error {
	if c.client == nil {
		return nil
	}

	return c.client.Close()
}
