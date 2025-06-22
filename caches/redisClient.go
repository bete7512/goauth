package caches

import (
	"context"
	"log"
	"strconv" 
	"time"

	"github.com/bete7512/goauth/config"
	"github.com/redis/go-redis/v9"
)

// RedisClient is a wrapper around the Redis client
type RedisClient struct {
	Client *redis.Client
	Ctx    context.Context
}

// NewRedisClient creates a new Redis client
func NewRedisClient(config config.RedisConfig) *RedisClient {
	// Convert port to string properly
	portStr := strconv.Itoa(config.Port)

	client := redis.NewClient(&redis.Options{
		Addr:     config.Host + ":" + portStr,
		Password: config.Password,
		DB:       config.Database,
	})

	if err := client.Ping(context.Background()).Err(); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
		return nil
	}

	return &RedisClient{
		Client: client,
		Ctx:    context.Background(),
	}
}

// Get retrieves a value from Redis
func (r *RedisClient) Get(key string) (string, error) {
	return r.Client.Get(r.Ctx, key).Result()
}

// Set stores a value in Redis
func (r *RedisClient) Set(key string, value interface{}, expiration time.Duration) error {
	return r.Client.Set(r.Ctx, key, value, expiration).Err()
}

// Del removes a key from Redis
func (r *RedisClient) Del(key string) error {
	return r.Client.Del(r.Ctx, key).Err()
}

// Exists checks if a key exists in Redis
func (r *RedisClient) Exists(key string) (bool, error) {
	result, err := r.Client.Exists(r.Ctx, key).Result()
	return result > 0, err
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	return r.Client.Close()
}

// SetNX sets a value if the key doesn't exist
func (r *RedisClient) SetNX(key string, value interface{}, expiration time.Duration) (bool, error) {
	return r.Client.SetNX(r.Ctx, key, value, expiration).Result()
}

// Incr increments a key's value
func (r *RedisClient) Incr(key string) (int64, error) {
	return r.Client.Incr(r.Ctx, key).Result()
}

// Expire sets an expiration time on a key
func (r *RedisClient) Expire(key string, expiration time.Duration) (bool, error) {
	return r.Client.Expire(r.Ctx, key, expiration).Result()
}
