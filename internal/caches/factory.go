package caches

import (
	"fmt"

	"github.com/bete7512/goauth/internal/caches/memory"
	"github.com/bete7512/goauth/internal/caches/redis"
	"github.com/bete7512/goauth/internal/caches/valkey"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

// NewCacheFactory creates a new cache factory based on the configuration
func NewCacheFactory(conf config.Config) (interfaces.CacheFactory, error) {
	// If caching is disabled, return a memory cache
	if !conf.Cache.Enabled {
		return memory.NewCacheFactory(conf.Cache.DefaultTTL), nil
	}
	switch conf.Cache.Type {
	case config.RedisCache:
		return redis.NewCacheFactory(conf.Cache.Redis), nil
	case config.MemoryCache:
		return memory.NewCacheFactory(conf.Cache.DefaultTTL), nil
	case config.ValkeyCache:
		return valkey.NewCacheFactory(conf.Cache.Valkey), nil
	case config.CustomCache:
		if conf.Cache.EnableCustomCache && conf.Cache.CustomCache.Factory != nil {
			return conf.Cache.CustomCache.Factory, nil
		}
		return nil, fmt.Errorf("custom cache factory not provided")
	case config.NoCache:
		return memory.NewCacheFactory(conf.Cache.DefaultTTL), nil
	default:
		// Default to memory cache
		return memory.NewCacheFactory(conf.Cache.DefaultTTL), nil
	}
}
