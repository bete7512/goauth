package ratelimiter

import (
	"errors"
	"strconv"
	"time"

	"github.com/bete7512/goauth/internal/caches"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/redis/go-redis/v9"
)

type RedisRateLimiter struct {
	client caches.RedisClient
	config config.RateLimiterConfig
}

func NewRedisRateLimiter(conf config.Config) (*RedisRateLimiter, error) {
	redisClient := caches.NewRedisClient(conf.Redis)
	if redisClient == nil {
		return nil, errors.New("failed to create Redis client")
	}

	return &RedisRateLimiter{
		client: *redisClient,
		config: conf.Security.RateLimiter,
	}, nil
}

// Allow checks if a request is allowed using simple Redis operations
func (r *RedisRateLimiter) Allow(key string, windowSize time.Duration, maxRequests int, blockDuration time.Duration) bool {
	return r.AllowN(key, windowSize, maxRequests, blockDuration, 1)
}

// AllowN allows multiple requests at once - FIXED VERSION
func (r *RedisRateLimiter) AllowN(key string, windowSize time.Duration, maxRequests int, blockDuration time.Duration, n int) bool {
	if n <= 0 {
		return true
	}

	ctx := r.client.Ctx
	prefixedKey := "ratelimit:" + key
	blockKey := prefixedKey + ":blocked"
	windowKey := prefixedKey + ":window"

	// Use pipeline for better performance and some atomicity
	pipe := r.client.Client.Pipeline()

	// Check if blocked
	existsCmd := pipe.Exists(ctx, blockKey)
	
	now := time.Now().Unix()
	windowStart := now - int64(windowSize.Seconds())

	// Clean up old entries
	pipe.ZRemRangeByScore(ctx, windowKey, "0", strconv.FormatInt(windowStart, 10))
	
	// Get current count
	countCmd := pipe.ZCard(ctx, windowKey)

	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false
	}

	// Check results
	blocked, err := existsCmd.Result()
	if err != nil || blocked > 0 {
		return false
	}

	count, err := countCmd.Result()
	if err != nil {
		count = 0
	}

	// Check if adding n requests would exceed limit
	if count+int64(n) > int64(maxRequests) {
		if blockDuration > 0 {
			r.client.Client.SetEx(ctx, blockKey, "1", blockDuration)
		}
		return false
	}

	// Add n requests in a single ZAdd operation
	if n > 0 {
		members := make([]redis.Z, n)
		for i := 0; i < n; i++ {
			uniqueMember := strconv.FormatInt(now, 10) + ":" + strconv.Itoa(i) + ":" + strconv.FormatInt(time.Now().UnixNano(), 10)
			members[i] = redis.Z{Score: float64(now), Member: uniqueMember}
		}

		_, err = r.client.Client.ZAdd(ctx, windowKey, members...).Result()
		if err != nil {
			return false
		}

		// Set expiration (with error handling)
		err = r.client.Client.Expire(ctx, windowKey, windowSize+time.Minute).Err()
		if err != nil {
			// Log error but don't fail the request
			// In production, you might want to log this
		}
	}

	return true
}

// GetStats returns current statistics for a key
func (r *RedisRateLimiter) GetStats(key string, windowSize time.Duration) (currentRequests int64, isBlocked bool, blockedUntil time.Time) {
	ctx := r.client.Ctx
	prefixedKey := "ratelimit:" + key
	blockKey := prefixedKey + ":blocked"
	windowKey := prefixedKey + ":window"

	pipe := r.client.Client.Pipeline()

	// Check if blocked
	ttlCmd := pipe.TTL(ctx, blockKey)

	// Clean up old entries first
	now := time.Now().Unix()
	windowStart := now - int64(windowSize.Seconds())
	pipe.ZRemRangeByScore(ctx, windowKey, "0", strconv.FormatInt(windowStart, 10))

	// Get current count
	countCmd := pipe.ZCard(ctx, windowKey)

	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, false, time.Time{}
	}

	// Process results
	ttl, err := ttlCmd.Result()
	if err == nil && ttl > 0 {
		isBlocked = true
		blockedUntil = time.Now().Add(ttl)
	}

	count, err := countCmd.Result()
	if err == nil {
		currentRequests = count
	}

	return
}

// Reset clears all rate limit data for a key
func (r *RedisRateLimiter) Reset(key string) error {
	ctx := r.client.Ctx
	prefixedKey := "ratelimit:" + key
	blockKey := prefixedKey + ":blocked"
	windowKey := prefixedKey + ":window"

	pipe := r.client.Client.Pipeline()
	pipe.Del(ctx, blockKey)
	pipe.Del(ctx, windowKey)
	_, err := pipe.Exec(ctx)

	return err
}

// Close closes the Redis client
func (r *RedisRateLimiter) Close() error {
	return r.client.Close()
}

// Additional helper method for cleanup
func (r *RedisRateLimiter) CleanupExpiredKeys() error {
	ctx := r.client.Ctx
	
	// Get all rate limit keys
	keys, err := r.client.Client.Keys(ctx, "ratelimit:*:window").Result()
	if err != nil {
		return err
	}

	pipe := r.client.Client.Pipeline()
	now := time.Now().Unix()

	for _, key := range keys {
		// Remove entries older than 24 hours as a safety cleanup
		oldestAllowed := now - 24*60*60
		pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(oldestAllowed, 10))
	}

	_, err = pipe.Exec(ctx)
	return err
}