package ratelimiter

import (
	"errors"
	"log"
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

// Allow checks if a request is allowed based on rate limiting rules
func (r *RedisRateLimiter) Allow(key string, windowSize time.Duration, maxRequests int, blockDuration time.Duration) bool {
	prefixedKey := "ratelimit:" + key
	now := time.Now().Unix()
	windowKey := prefixedKey + ":window"
	blockKey := prefixedKey + ":blocked"
	// Check if the key is blocked
	blocked, err := r.client.Exists(blockKey)
	if err != nil {
		return false
	}

	if blocked {
		return false
	}

	pingCmd := r.client.Client.Ping(r.client.Ctx)
	if err := pingCmd.Err(); err != nil {
		return false
	}

	// Check if the window key exists first
	existsCmd := r.client.Client.Exists(r.client.Ctx, windowKey)
	exists, err := existsCmd.Result()
	if err != nil {
		return false
	}
	// Get all current entries for debugging
	if exists > 0 {
		allEntries := r.client.Client.ZRangeWithScores(r.client.Ctx, windowKey, 0, -1)
		entries, err := allEntries.Result()
		if err != nil {
			log.Printf("Error getting all entries: %v", err)
		} else {
			log.Printf("Current entries in %s before cleanup: %d", windowKey, len(entries))
			for i, entry := range entries {
				if i < 5 { // Only show first 5 for brevity
					log.Printf("Entry: %v, Score: %v", entry.Member, entry.Score)
				}
			}
		}
	}

	// First, clean up old timestamps outside the window
	windowStart := now - int64(windowSize.Seconds())
	cleanupCmd := r.client.Client.ZRemRangeByScore(r.client.Ctx, windowKey, "0", strconv.FormatInt(windowStart, 10))
	if err := cleanupCmd.Err(); err != nil {
		log.Printf("Error cleaning up old timestamps: %v", err)
	} else {
		removed, _ := cleanupCmd.Result()
		log.Printf("Removed %d old entries", removed)
	}

	// Get the count of requests in the current window
	countCmd := r.client.Client.ZCard(r.client.Ctx, windowKey)
	count, err := countCmd.Result()
	if err != nil {
		log.Printf("Error getting count: %v", err)
		count = 0 // Assume new set
	}

	log.Printf("Current request count for %s: %d, max: %d", prefixedKey, count, maxRequests)

	// If count exceeds max requests, block the key
	if count >= int64(maxRequests) {
		log.Printf("Rate limit exceeded for %s, blocking for %v", prefixedKey, blockDuration)
		setCmd := r.client.Client.Set(r.client.Ctx, blockKey, "1", blockDuration)
		if err := setCmd.Err(); err != nil {
			log.Printf("Error setting block key: %v", err)
		}
		return false
	}

	// Add this request with current timestamp
	uniqueMember := strconv.FormatInt(now, 10) + ":" + strconv.FormatInt(time.Now().UnixNano(), 10)
	log.Printf("Adding entry with score %d, member %s", now, uniqueMember)

	addCmd := r.client.Client.ZAdd(r.client.Ctx, windowKey,
		redis.Z{
			Score:  float64(now),
			Member: uniqueMember, // Ensure uniqueness
		})

	if err := addCmd.Err(); err != nil {
		log.Printf("Error adding request: %v", err)
		return false
	}

	// Set expiration on the window key to ensure cleanup
	expireCmd := r.client.Client.Expire(r.client.Ctx, windowKey, windowSize+time.Second)
	if err := expireCmd.Err(); err != nil {
		log.Printf("Error setting expiration: %v", err)
	}

	// Verify the entry was added
	verifyCount := r.client.Client.ZCard(r.client.Ctx, windowKey)
	newCount, err := verifyCount.Result()
	if err != nil {
		log.Printf("Error verifying count: %v", err)
	} else {
		log.Printf("Updated count for %s: %d", prefixedKey, newCount)
	}

	return true
}

func (r *RedisRateLimiter) Close() error {
	return r.client.Close()
}
