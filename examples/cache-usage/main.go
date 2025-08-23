package main

// import (
// 	"context"
// 	"fmt"
// 	"log"
// 	"time"

// 	"github.com/bete7512/goauth/internal/caches"
// 	"github.com/bete7512/goauth/internal/services"
// 	"github.com/bete7512/goauth/pkg/config"
// 	"github.com/bete7512/goauth/pkg/interfaces"
// )

// // CustomCache implements a custom cache for demonstration
// type CustomCache struct {
// 	data map[string]interface{}
// }

// type CustomCacheFactory struct {
// 	cache *CustomCache
// }

// func NewCustomCache() interfaces.Cache {
// 	return &CustomCache{
// 		data: make(map[string]interface{}),
// 	}
// }

// func (f *CustomCacheFactory) GetCache() interfaces.Cache {
// 	return f.cache
// }

// func (c *CustomCache) Get(ctx context.Context, key string) (interface{}, error) {
// 	if value, exists := c.data[key]; exists {
// 		return value, nil
// 	}
// 	return nil, interfaces.ErrCacheKeyNotFound
// }

// func (c *CustomCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
// 	c.data[key] = value
// 	return nil
// }

// func (c *CustomCache) Delete(ctx context.Context, key string) error {
// 	delete(c.data, key)
// 	return nil
// }

// func (c *CustomCache) Exists(ctx context.Context, key string) (bool, error) {
// 	_, exists := c.data[key]
// 	return exists, nil
// }

// func (c *CustomCache) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
// 	if _, exists := c.data[key]; exists {
// 		return false, nil
// 	}
// 	c.data[key] = value
// 	return true, nil
// }

// func (c *CustomCache) Incr(ctx context.Context, key string) (int64, error) {
// 	if value, exists := c.data[key]; exists {
// 		if counter, ok := value.(int64); ok {
// 			counter++
// 			c.data[key] = counter
// 			return counter, nil
// 		}
// 	}
// 	c.data[key] = int64(1)
// 	return 1, nil
// }

// func (c *CustomCache) Expire(ctx context.Context, key string, expiration time.Duration) (bool, error) {
// 	_, exists := c.data[key]
// 	return exists, nil
// }

// func (c *CustomCache) TTL(ctx context.Context, key string) (time.Duration, error) {
// 	_, exists := c.data[key]
// 	if exists {
// 		return time.Hour, nil // Mock TTL
// 	}
// 	return -1, nil
// }

// func (c *CustomCache) Close() error {
// 	c.data = make(map[string]interface{})
// 	return nil
// }

// func main() {
// 	// Example 1: Using Memory Cache
// 	fmt.Println("=== Memory Cache Example ===")
// 	memoryConfig := config.Config{
// 		Cache: config.CacheConfig{
// 			Type:       config.MemoryCache,
// 			Enabled:    true,
// 			DefaultTTL: 5 * time.Minute,
// 		},
// 	}

// 	memoryFactory, err := caches.NewCacheFactory(memoryConfig)
// 	if err != nil {
// 		log.Fatal("Failed to create memory cache factory:", err)
// 	}

// 	memoryCache := memoryFactory.GetCache()
// 	cacheService := services.NewCacheService(memoryCache)

// 	// Test memory cache
// 	testCache(cacheService, "memory")

// 	// Example 2: Using Redis Cache
// 	fmt.Println("\n=== Redis Cache Example ===")
// 	redisConfig := config.Config{
// 		Cache: config.CacheConfig{
// 			Type:    config.RedisCache,
// 			Enabled: true,
// 			Redis: config.RedisConfig{
// 				Host:     "localhost",
// 				Port:     6379,
// 				Database: 0,
// 				Password: "",
// 			},
// 		},
// 	}

// 	redisFactory, err := caches.NewCacheFactory(redisConfig)
// 	if err != nil {
// 		log.Printf("Failed to create Redis cache factory: %v (this is expected if Redis is not running)", err)
// 	} else {
// 		redisCache := redisFactory.GetCache()
// 		redisCacheService := services.NewCacheService(redisCache)
// 		testCache(redisCacheService, "redis")
// 	}

// 	// Example 3: Using Custom Cache
// 	fmt.Println("\n=== Custom Cache Example ===")
// 	customConfig := config.Config{
// 		Cache: config.CacheConfig{
// 			Type:             config.CustomCache,
// 			Enabled:          true,
// 			EnableCustomCache: true,
// 			CustomCache: config.CustomCacheConfig{
// 				Factory: &CustomCacheFactory{
// 					cache: &CustomCache{
// 						data: make(map[string]interface{}),
// 					},
// 				},
// 			},
// 		},
// 	}

// 	customFactory, err := caches.NewCacheFactory(customConfig)
// 	if err != nil {
// 		log.Fatal("Failed to create custom cache factory:", err)
// 	}

// 	customCache := customFactory.GetCache()
// 	customCacheService := services.NewCacheService(customCache)

// 	testCache(customCacheService, "custom")

// 	// Example 4: Using No Cache (disabled)
// 	fmt.Println("\n=== No Cache Example ===")
// 	noCacheConfig := config.Config{
// 		Cache: config.CacheConfig{
// 			Type:    config.NoCache,
// 			Enabled: false,
// 		},
// 	}

// 	noCacheFactory, err := caches.NewCacheFactory(noCacheConfig)
// 	if err != nil {
// 		log.Fatal("Failed to create no-cache factory:", err)
// 	}

// 	noCache := noCacheFactory.GetCache()
// 	noCacheService := services.NewCacheService(noCache)

// 	testCache(noCacheService, "no-cache")

// 	// Example 5: Advanced Cache Usage
// 	fmt.Println("\n=== Advanced Cache Usage Example ===")
// 	advancedCacheUsage(cacheService)
// }

// func testCache(cacheService *services.CacheService, cacheType string) {
// 	ctx := context.Background()

// 	// Test basic operations
// 	fmt.Printf("Testing %s cache...\n", cacheType)

// 	// Set a value
// 	err := cacheService.Set(ctx, "test:key", "test:value", 1*time.Minute)
// 	if err != nil {
// 		fmt.Printf("Failed to set value in %s cache: %v\n", cacheType, err)
// 		return
// 	}

// 	// Get the value
// 	var value string
// 	err = cacheService.Get(ctx, "test:key", &value)
// 	if err != nil {
// 		fmt.Printf("Failed to get value from %s cache: %v\n", cacheType, err)
// 		return
// 	}
// 	fmt.Printf("Retrieved value from %s cache: %s\n", cacheType, value)

// 	// Test exists
// 	exists, err := cacheService.Exists(ctx, "test:key")
// 	if err != nil {
// 		fmt.Printf("Failed to check existence in %s cache: %v\n", cacheType, err)
// 		return
// 	}
// 	fmt.Printf("Key exists in %s cache: %v\n", cacheType, exists)

// 	// Test increment
// 	counter, err := cacheService.Incr(ctx, "test:counter")
// 	if err != nil {
// 		fmt.Printf("Failed to increment counter in %s cache: %v\n", cacheType, err)
// 		return
// 	}
// 	fmt.Printf("Counter value in %s cache: %d\n", cacheType, counter)

// 	// Test TTL
// 	ttl, err := cacheService.TTL(ctx, "test:key")
// 	if err != nil {
// 		fmt.Printf("Failed to get TTL from %s cache: %v\n", cacheType, err)
// 		return
// 	}
// 	fmt.Printf("TTL for key in %s cache: %v\n", cacheType, ttl)

// 	// Clean up
// 	cacheService.Delete(ctx, "test:key")
// 	cacheService.Delete(ctx, "test:counter")
// }

// func advancedCacheUsage(cacheService *services.CacheService) {
// 	ctx := context.Background()

// 	// Example: Caching user data
// 	userID := "user123"
// 	userData := map[string]interface{}{
// 		"id":    userID,
// 		"name":  "John Doe",
// 		"email": "john@example.com",
// 		"roles": []string{"user", "admin"},
// 	}

// 	// Cache user data
// 	err := cacheService.CacheUser(ctx, userID, userData, 30*time.Minute)
// 	if err != nil {
// 		fmt.Printf("Failed to cache user data: %v\n", err)
// 		return
// 	}

// 	// Retrieve cached user data
// 	var cachedUser map[string]interface{}
// 	err = cacheService.GetCachedUser(ctx, userID, &cachedUser)
// 	if err != nil {
// 		fmt.Printf("Failed to get cached user data: %v\n", err)
// 		return
// 	}
// 	fmt.Printf("Retrieved cached user data: %+v\n", cachedUser)

// 	// Example: GetOrSet pattern
// 	var result string
// 	err = cacheService.GetOrSet(ctx, "expensive:operation", &result, func() (interface{}, error) {
// 		// Simulate expensive operation
// 		time.Sleep(100 * time.Millisecond)
// 		return "expensive result", nil
// 	}, 5*time.Minute)
// 	if err != nil {
// 		fmt.Printf("Failed to get or set: %v\n", err)
// 		return
// 	}
// 	fmt.Printf("GetOrSet result: %s\n", result)

// 	// Example: Atomic operations with SetNX
// 	success, err := cacheService.SetNX(ctx, "lock:resource", "locked", 1*time.Minute)
// 	if err != nil {
// 		fmt.Printf("Failed to set lock: %v\n", err)
// 		return
// 	}
// 	fmt.Printf("Lock acquired: %v\n", success)

// 	// Try to acquire the same lock again (should fail)
// 	success, err = cacheService.SetNX(ctx, "lock:resource", "locked", 1*time.Minute)
// 	if err != nil {
// 		fmt.Printf("Failed to set lock: %v\n", err)
// 		return
// 	}
// 	fmt.Printf("Second lock attempt: %v\n", success)

// 	// Clean up
// 	cacheService.Delete(ctx, "lock:resource")
// 	cacheService.InvalidateUserCache(ctx, userID)
// 	cacheService.Delete(ctx, "expensive:operation")
// } 