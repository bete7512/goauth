package ratelimiter

import (
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type RateLimiter struct {
	Auth config.Auth
}

func New(auth config.Auth) (interfaces.RateLimiter, error) {

	switch auth.Config.Cache.Type {
	case config.CacheType(config.MemoryCache):
		rateLimiter, err := NewMemoryRateLimiter(auth)
		if err != nil {
			return nil, err
		}
		return rateLimiter, nil
	case config.CacheType(config.RedisCache), config.CacheType(config.ValkeyCache), config.CacheType(config.CustomCache):
		rateLimiter, err := NewCacheRateLimiter(auth)
		if err != nil {
			return nil, err
		}
		return rateLimiter, nil
	default:
		rateLimiter, err := NewMemoryRateLimiter(auth)
		if err != nil {
			return nil, err
		}
		return rateLimiter, nil
	}
}
