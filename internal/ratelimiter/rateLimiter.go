package ratelimiter

import (
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type RateLimiter struct {
	Conf config.Config
}

func New(conf config.Config) (interfaces.RateLimiter, error) {

	switch conf.Security.RateLimiter.Type {
	case config.MemoryRateLimiter:
		rateLimiter, err := NewMemoryRateLimiter(conf)
		if err != nil {
			return nil, err
		}
		return rateLimiter, nil
	case config.RedisRateLimiter:
		rateLimiter, err := NewRedisRateLimiter(conf)
		if err != nil {
			return nil, err
		}
		return rateLimiter, nil
	default:
		rateLimiter, err := NewMemoryRateLimiter(conf)
		if err != nil {
			return nil, err
		}
		return rateLimiter, nil
	}
}
