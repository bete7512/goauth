package ratelimiter

import (
	"github.com/bete7512/goauth/types"
)


func NewRateLimiter(config types.Config) types.RateLimiter {

	switch config.RateLimiter.Type {
	case types.MemoryRateLimiter:
		rateLimiter, err := NewMemoryRateLimiter(config)
		if err != nil {
			return nil
		}
		return rateLimiter
	case types.RedisRateLimiter:
		rateLimiter, err := NewRedisRateLimiter(config)
		if err != nil {
			return nil
		}
		return rateLimiter
	default:
		rateLimiter, err := NewMemoryRateLimiter(config)
		if err != nil {
			return nil
		}
		return rateLimiter
	}
}
