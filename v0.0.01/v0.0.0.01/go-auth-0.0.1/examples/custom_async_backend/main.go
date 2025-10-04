package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/bete7512/goauth/internal/storage"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
)

// Example 1: Custom Redis-like Backend
type CustomRedisBackend struct {
	events []string
}

func (b *CustomRedisBackend) Publish(ctx context.Context, eventType string, event interface{}) error {
	data, _ := json.Marshal(map[string]interface{}{
		"type": eventType,
		"data": event,
	})
	b.events = append(b.events, string(data))
	fmt.Printf("📤 Published to Redis: %s\n", string(data))
	return nil
}

func (b *CustomRedisBackend) Close() error {
	fmt.Println("🔌 Closing Redis connection")
	return nil
}

func (b *CustomRedisBackend) Name() string {
	return "custom-redis"
}

// Example 2: Custom Queue Backend
type CustomQueueBackend struct {
	queueName string
}

func (b *CustomQueueBackend) Publish(ctx context.Context, eventType string, event interface{}) error {
	fmt.Printf("📨 Sent to queue [%s]: %s\n", b.queueName, eventType)
	return nil
}

func (b *CustomQueueBackend) Close() error {
	fmt.Println("🔌 Closing queue connection")
	return nil
}

func (b *CustomQueueBackend) Name() string {
	return "custom-queue"
}

func main() {
	// Create storage
	store, err := storage.NewStorage(config.StorageConfig{
		Driver:  "gorm",
		Dialect: "sqlite",
		DSN:     "./auth.db",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Option 1: Default worker pool (no custom backend)
	fmt.Println("\n=== Option 1: Default Worker Pool ===")
	auth1, _ := auth.New(&config.Config{
		Storage:   store,
		SecretKey: "secret",
		// AsyncBackend: nil = uses default worker pool
	})
	fmt.Println("✅ Using default worker pool backend")
	auth1.Close()

	// Option 2: Custom Redis backend
	fmt.Println("\n=== Option 2: Custom Redis Backend ===")
	redisBackend := &CustomRedisBackend{}
	auth2, _ := auth.New(&config.Config{
		Storage:      store,
		SecretKey:    "secret",
		AsyncBackend: redisBackend,
	})
	fmt.Println("✅ Using custom Redis backend")

	// Simulate event emission
	// In real code, this happens automatically when users signup/login
	auth2.Close()

	// Option 3: Custom queue backend
	fmt.Println("\n=== Option 3: Custom Queue Backend ===")
	queueBackend := &CustomQueueBackend{queueName: "goauth-events"}
	auth3, _ := auth.New(&config.Config{
		Storage:      store,
		SecretKey:    "secret",
		AsyncBackend: queueBackend,
	})
	fmt.Println("✅ Using custom queue backend")
	auth3.Close()

	fmt.Println("\n🎉 All backends work seamlessly!")
}
