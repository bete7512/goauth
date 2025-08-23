package ratelimiter

import (
	"context"
	"strconv"
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type CacheRateLimiter struct {
	Auth config.Auth
}

func NewCacheRateLimiter(auth config.Auth) (interfaces.RateLimiter, error) {
	return &CacheRateLimiter{
		Auth: auth,
	}, nil
}

// Allow checks if a request is allowed using cache operations
func (r *CacheRateLimiter) Allow(ctx context.Context, key string, windowSize time.Duration, maxRequests int, blockDuration time.Duration) bool {
	return r.AllowN(ctx, key, windowSize, maxRequests, blockDuration, 1)
}

// AllowN allows multiple requests at once using cache operations
func (r *CacheRateLimiter) AllowN(ctx context.Context, key string, windowSize time.Duration, maxRequests int, blockDuration time.Duration, n int) bool {
	if n <= 0 {
		return true
	}

	prefixedKey := "ratelimit:" + key
	blockKey := prefixedKey + ":blocked"
	windowKey := prefixedKey + ":window"

	// Check if blocked
	blocked, err := r.Auth.Cache.Exists(context.Background(), blockKey)
	if err != nil {
		return false
	}
	if blocked {
		return false
	}

	// Get current count from cache
	countValue, err := r.Auth.Cache.Get(ctx, windowKey)
	if err != nil && err != interfaces.ErrCacheKeyNotFound {
		return false
	}

	var count int64
	if countValue != nil {
		if countStr, ok := countValue.(string); ok {
			if parsed, err := strconv.ParseInt(countStr, 10, 64); err == nil {
				count = parsed
			}
		} else if countInt, ok := countValue.(int64); ok {
			count = countInt
		}
	}

	// Check if adding n requests would exceed limit
	if count+int64(n) > int64(maxRequests) {
		if blockDuration > 0 {
			r.Auth.Cache.Set(ctx, blockKey, "1", blockDuration)
		}
		return false
	}

	// Add n requests
	if n > 0 {
		newCount := count + int64(n)
		err = r.Auth.Cache.Set(ctx, windowKey, strconv.FormatInt(newCount, 10), windowSize+time.Minute)
		if err != nil {
			return false
		}
	}

	return true
}

// GetStats returns current statistics for a key
func (r *CacheRateLimiter) GetStats(ctx context.Context, key string, windowSize time.Duration) (currentRequests int64, isBlocked bool, blockedUntil time.Time) {
	prefixedKey := "ratelimit:" + key
	blockKey := prefixedKey + ":blocked"
	windowKey := prefixedKey + ":window"

	// Check if blocked
	blocked, err := r.Auth.Cache.Exists(ctx, blockKey)
	if err == nil && blocked {
		isBlocked = true
		// Get TTL for blocked key
		ttl, err := r.Auth.Cache.TTL(ctx, blockKey)
		if err == nil && ttl > 0 {
			blockedUntil = time.Now().Add(ttl)
		}
	}

	// Get current count
	countValue, err := r.Auth.Cache.Get(ctx, windowKey)
	if err == nil && countValue != nil {
		if countStr, ok := countValue.(string); ok {
			if parsed, err := strconv.ParseInt(countStr, 10, 64); err == nil {
				currentRequests = parsed
			}
		} else if countInt, ok := countValue.(int64); ok {
			currentRequests = countInt
		}
	}

	return
}

// Reset clears all rate limit data for a key
func (r *CacheRateLimiter) Reset(ctx context.Context, key string) error {
	prefixedKey := "ratelimit:" + key
	blockKey := prefixedKey + ":blocked"
	windowKey := prefixedKey + ":window"

	// Delete both keys
	err1 := r.Auth.Cache.Delete(ctx, blockKey)
	err2 := r.Auth.Cache.Delete(ctx, windowKey)

	if err1 != nil {
		return err1
	}
	return err2
}

// Close closes the cache connection
func (r *CacheRateLimiter) Close() error {
	return r.Auth.Cache.Close()
}

// CleanupExpiredKeys cleans up expired rate limit keys
func (r *CacheRateLimiter) CleanupExpiredKeys() error {
	// This is a simplified cleanup - in a real implementation,
	// you might want to iterate through keys and clean up expired ones
	// For now, we'll rely on the cache's built-in expiration
	return nil
}
