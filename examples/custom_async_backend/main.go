package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/bete7512/goauth/internal/storage"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/nats-io/nats.go"
)

// Example 1: Custom Redis-like Backend
type CustomRedisBackend struct {
	events []string
}

func (b *CustomRedisBackend) Publish(ctx context.Context, eventType types.EventType, event *types.Event) error {
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

func (b *CustomQueueBackend) Publish(ctx context.Context, eventType types.EventType, event *types.Event) error {
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

// nats jetstream
type NatsJetstreamBackend struct {
	conn *nats.Conn
	js   nats.JetStreamContext
}

func (b *NatsJetstreamBackend) Publish(ctx context.Context, eventType types.EventType, event *types.Event) error {
	fmt.Printf("📨 Sent to queue [%s]: %s\n", b.conn.ConnectedServerName(), eventType)
	data, _ := json.Marshal(event)
	_, err := b.js.Publish(string(eventType), data)
	if err != nil {
		return err
	}
	return nil
}

func (b *NatsJetstreamBackend) Close() error {
	b.conn.Close()
	fmt.Println("🔌 Closing nats connection")
	return nil
}

func (b *NatsJetstreamBackend) Name() string {
	return "nats-jetstream"
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
		Storage: store,
		Security: config.SecurityConfig{
			JwtSecretKey: "secret",
		},
		// AsyncBackend: nil = uses default worker pool
	})
	fmt.Println("✅ Using default worker pool backend")
	auth1.Close()

	// Option 2: Custom Redis backend
	fmt.Println("\n=== Option 2: Custom Redis Backend ===")
	redisBackend := &CustomRedisBackend{}
	auth2, _ := auth.New(&config.Config{
		Storage: store,
		Security: config.SecurityConfig{
			JwtSecretKey: "secret",
		},
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
		Storage: store,
		Security: config.SecurityConfig{
			JwtSecretKey: "secret",
		},
		AsyncBackend: queueBackend,
	})
	fmt.Println("✅ Using custom queue backend")
	auth3.Close()

	// Option 4: Nats jetstream backend
	fmt.Println("\n=== Option 4: Nats Jetstream Backend ===")
	conn, err := nats.Connect("nats://localhost:4222")
	if err != nil {
		log.Fatal(err)
	}
	js, err := conn.JetStream()
	if err != nil {
		log.Fatal(err)
	}
	jetstreamBackend := &NatsJetstreamBackend{conn: conn, js: js}
	auth4, _ := auth.New(&config.Config{
		Storage: store,
		Security: config.SecurityConfig{
			JwtSecretKey: "secret",
		},
		AsyncBackend: jetstreamBackend,
	})
	fmt.Println("✅ Using nats jetstream backend")
	auth4.Close()

	fmt.Println("\n🎉 All backends work seamlessly!")
}
