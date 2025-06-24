package ratelimiter

import "github.com/bete7512/goauth/config"

func NewRateLimiter(conf config.Config) config.RateLimiter {

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
