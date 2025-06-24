package ratelimiter

import (
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type RateLimiter struct {
	Conf config.Config
}

func New(conf config.Config) interfaces.RateLimiter {

	switch conf.Security.RateLimiter.Type {
	case config.MemoryRateLimiter:
		rateLimiter, err := NewMemoryRateLimiter(conf)
		if err != nil {
			return nil
		}
		return rateLimiter
	case config.RedisRateLimiter:
		rateLimiter, err := NewRedisRateLimiter(conf)
		if err != nil {
			return nil
		}
		return rateLimiter
	default:
		rateLimiter, err := NewMemoryRateLimiter(conf)
		if err != nil {
			return nil
		}
		return rateLimiter
	}
}
