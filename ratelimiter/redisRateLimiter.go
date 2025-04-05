package ratelimiter

import (
	"errors"
	"log"
	"strconv"
	"time"

	"github.com/bete7512/goauth/caches"
	"github.com/bete7512/goauth/types"
	"github.com/redis/go-redis/v9"
)

type RedisRateLimiter struct {
	client caches.RedisClient
	config types.RateLimiterConfig
}

func NewRedisRateLimiter(config types.Config) (*RedisRateLimiter, error) {
	redisClient := caches.NewRedisClient(config.RedisConfig)
	if redisClient == nil {
		return nil, errors.New("failed to create Redis client")
	}

	return &RedisRateLimiter{
		client: *redisClient,
		config: config.RateLimiter,
	}, nil
}

// Allow checks if a request is allowed based on rate limiting rules
func (r *RedisRateLimiter) Allow(key string, config types.LimiterConfig) bool {
	prefixedKey := "ratelimit:" + key
	now := time.Now().Unix()
	windowKey := prefixedKey + ":window"
	blockKey := prefixedKey + ":blocked"

	log.Printf("Rate limit check for key: %s", prefixedKey)

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
	windowStart := now - int64(config.WindowSize.Seconds())
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

	log.Printf("Current request count for %s: %d, max: %d", prefixedKey, count, config.MaxRequests)

	// If count exceeds max requests, block the key
	if count >= int64(config.MaxRequests) {
		log.Printf("Rate limit exceeded for %s, blocking for %v", prefixedKey, config.BlockDuration)
		setCmd := r.client.Client.Set(r.client.Ctx, blockKey, "1", config.BlockDuration)
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
	expireCmd := r.client.Client.Expire(r.client.Ctx, windowKey, config.WindowSize+time.Second)
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

// BruteForceProtection implements protection against brute force attacks
func (r *RedisRateLimiter) BruteForceProtection(identifier string, config types.BruteForceConfig) bool {
	prefixedIdentifier := "bruteforce:" + identifier
	now := time.Now()
	attemptsKey := prefixedIdentifier + ":attempts"
	blockKey := prefixedIdentifier + ":blocked"
	lastAttemptKey := prefixedIdentifier + ":lastAttempt"
	blockDurationKey := prefixedIdentifier + ":blockDuration"

	// Check if the identifier is blocked
	blocked, err := r.client.Exists(blockKey)
	if err != nil {
		log.Printf("Error checking if identifier is blocked: %v", err)
	}

	if blocked {
		log.Printf("Identifier is blocked for brute force protection: %s", prefixedIdentifier)
		return false
	}

	// Record the attempt
	attemptsStr, err := r.client.Get(attemptsKey)
	attempts := 1
	if err == nil {
		attempts, _ = strconv.Atoi(attemptsStr)
		attempts++
	}

	log.Printf("Brute force attempt count for %s: %d, max: %d", prefixedIdentifier, attempts, config.MaxAttempts)

	// Update the attempts count
	setCmd := r.client.Client.Set(r.client.Ctx, attemptsKey, strconv.Itoa(attempts), 24*time.Hour)
	if err := setCmd.Err(); err != nil {
		log.Printf("Error setting attempts: %v", err)
	}

	setLastCmd := r.client.Client.Set(r.client.Ctx, lastAttemptKey, strconv.FormatInt(now.Unix(), 10), 24*time.Hour)
	if err := setLastCmd.Err(); err != nil {
		log.Printf("Error setting last attempt: %v", err)
	}

	// If attempts exceed max attempts, block the identifier
	if attempts > config.MaxAttempts {
		blockDuration := config.InitialBlockDuration

		// If progressive blocking is enabled, increase block duration
		if config.ProgressiveBlocking {
			blockDurationStr, err := r.client.Get(blockDurationKey)
			if err == nil {
				currentBlockDuration, _ := time.ParseDuration(blockDurationStr)
				blockDuration = currentBlockDuration * 2
				if blockDuration > config.MaxBlockDuration {
					blockDuration = config.MaxBlockDuration
				}
			}

			setBlockDurCmd := r.client.Client.Set(r.client.Ctx, blockDurationKey, blockDuration.String(), 7*24*time.Hour)
			if err := setBlockDurCmd.Err(); err != nil {
				log.Printf("Error setting block duration: %v", err)
			}
		}

		log.Printf("Brute force protection activated for %s, blocking for %v", prefixedIdentifier, blockDuration)
		setBlockCmd := r.client.Client.Set(r.client.Ctx, blockKey, "1", blockDuration)
		if err := setBlockCmd.Err(); err != nil {
			log.Printf("Error setting block key: %v", err)
		}
		return false
	}

	return true
}

// Close closes the Redis connection
func (r *RedisRateLimiter) Close() error {
	return r.client.Close()
}
