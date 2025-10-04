# Async Event Backends

## Overview

The event system supports **pluggable async backends** for event processing. You can:

1. ✅ Use the **default worker pool** (built-in, no external dependencies)
2. ✅ Implement your own backend (Redis, RabbitMQ, Kafka, SQS, etc.)

## AsyncBackend Interface

```go
type AsyncBackend interface {
    // Publish sends an event to the async backend
    Publish(ctx context.Context, eventType EventType, event *Event) error

    // Close gracefully shuts down the backend
    Close() error

    // Name returns the backend name for logging
    Name() string
}
```

## Default Backend (Worker Pool)

**No configuration needed** - works out of the box with in-memory worker pool.

```go
// Uses default worker pool (10 workers, 1000 queue size)
eventBus := events.NewEventBus(logger)

// Custom worker pool size
backend := events.NewDefaultAsyncBackend(
    20,   // workers
    5000, // queue size
    logger,
)
eventBus := events.NewEventBusWithBackend(logger, backend)
```

## Custom Backend Implementation

### Example 1: Redis Backend

```go
package mybackends

import (
    "context"
    "encoding/json"
    "github.com/redis/go-redis/v9"
    "github.com/bete7512/goauth/internal/events"
)

type RedisBackend struct {
    client *redis.Client
    stream string
    logger events.Logger
}

func NewRedisBackend(addr, stream string, logger events.Logger) *RedisBackend {
    return &RedisBackend{
        client: redis.NewClient(&redis.Options{Addr: addr}),
        stream: stream,
        logger: logger,
    }
}

func (b *RedisBackend) Publish(ctx context.Context, eventType events.EventType, event *events.Event) error {
    data, err := json.Marshal(map[string]interface{}{
        "type": string(eventType),
        "data": event.Data,
    })
    if err != nil {
        return err
    }

    return b.client.XAdd(ctx, &redis.XAddArgs{
        Stream: b.stream,
        Values: map[string]interface{}{
            "event": string(data),
        },
    }).Err()
}

func (b *RedisBackend) Close() error {
    return b.client.Close()
}

func (b *RedisBackend) Name() string {
    return "redis-streams"
}
```

**Usage:**
```go
redisBackend := mybackends.NewRedisBackend("localhost:6379", "goauth:events", logger)
eventBus := events.NewEventBusWithBackend(logger, redisBackend)
```

### Example 2: RabbitMQ Backend

```go
package mybackends

import (
    "context"
    "encoding/json"
    amqp "github.com/rabbitmq/amqp091-go"
    "github.com/bete7512/goauth/internal/events"
)

type RabbitMQBackend struct {
    conn     *amqp.Connection
    channel  *amqp.Channel
    exchange string
    logger   events.Logger
}

func NewRabbitMQBackend(url, exchange string, logger events.Logger) (*RabbitMQBackend, error) {
    conn, err := amqp.Dial(url)
    if err != nil {
        return nil, err
    }

    ch, err := conn.Channel()
    if err != nil {
        return nil, err
    }

    // Declare exchange
    err = ch.ExchangeDeclare(exchange, "topic", true, false, false, false, nil)
    if err != nil {
        return nil, err
    }

    return &RabbitMQBackend{
        conn:     conn,
        channel:  ch,
        exchange: exchange,
        logger:   logger,
    }, nil
}

func (b *RabbitMQBackend) Publish(ctx context.Context, eventType events.EventType, event *events.Event) error {
    data, err := json.Marshal(map[string]interface{}{
        "type": string(eventType),
        "data": event.Data,
    })
    if err != nil {
        return err
    }

    return b.channel.PublishWithContext(
        ctx,
        b.exchange,       // exchange
        string(eventType), // routing key
        false,            // mandatory
        false,            // immediate
        amqp.Publishing{
            ContentType: "application/json",
            Body:        data,
        },
    )
}

func (b *RabbitMQBackend) Close() error {
    if b.channel != nil {
        b.channel.Close()
    }
    if b.conn != nil {
        return b.conn.Close()
    }
    return nil
}

func (b *RabbitMQBackend) Name() string {
    return "rabbitmq"
}
```

**Usage:**
```go
rmqBackend, _ := mybackends.NewRabbitMQBackend(
    "amqp://guest:guest@localhost:5672/",
    "goauth.events",
    logger,
)
eventBus := events.NewEventBusWithBackend(logger, rmqBackend)
```

### Example 3: AWS SQS Backend

```go
package mybackends

import (
    "context"
    "encoding/json"
    "github.com/aws/aws-sdk-go-v2/service/sqs"
    "github.com/bete7512/goauth/internal/events"
)

type SQSBackend struct {
    client   *sqs.Client
    queueURL string
    logger   events.Logger
}

func NewSQSBackend(client *sqs.Client, queueURL string, logger events.Logger) *SQSBackend {
    return &SQSBackend{
        client:   client,
        queueURL: queueURL,
        logger:   logger,
    }
}

func (b *SQSBackend) Publish(ctx context.Context, eventType events.EventType, event *events.Event) error {
    data, err := json.Marshal(map[string]interface{}{
        "type": string(eventType),
        "data": event.Data,
    })
    if err != nil {
        return err
    }

    _, err = b.client.SendMessage(ctx, &sqs.SendMessageInput{
        QueueUrl:    &b.queueURL,
        MessageBody: aws.String(string(data)),
        MessageAttributes: map[string]types.MessageAttributeValue{
            "EventType": {
                DataType:    aws.String("String"),
                StringValue: aws.String(string(eventType)),
            },
        },
    })

    return err
}

func (b *SQSBackend) Close() error {
    return nil // SQS client doesn't need explicit close
}

func (b *SQSBackend) Name() string {
    return "aws-sqs"
}
```

### Example 4: Apache Kafka Backend

```go
package mybackends

import (
    "context"
    "encoding/json"
    "github.com/segmentio/kafka-go"
    "github.com/bete7512/goauth/internal/events"
)

type KafkaBackend struct {
    writer *kafka.Writer
    logger events.Logger
}

func NewKafkaBackend(brokers []string, topic string, logger events.Logger) *KafkaBackend {
    return &KafkaBackend{
        writer: &kafka.Writer{
            Addr:     kafka.TCP(brokers...),
            Topic:    topic,
            Balancer: &kafka.LeastBytes{},
        },
        logger: logger,
    }
}

func (b *KafkaBackend) Publish(ctx context.Context, eventType events.EventType, event *events.Event) error {
    data, err := json.Marshal(map[string]interface{}{
        "type": string(eventType),
        "data": event.Data,
    })
    if err != nil {
        return err
    }

    return b.writer.WriteMessages(ctx, kafka.Message{
        Key:   []byte(string(eventType)),
        Value: data,
    })
}

func (b *KafkaBackend) Close() error {
    return b.writer.Close()
}

func (b *KafkaBackend) Name() string {
    return "kafka"
}
```

## Configuration in Auth Package

```go
package main

import (
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/internal/events"
)

func main() {
    // Option 1: Default worker pool (no config needed)
    authInstance, _ := auth.New(&config.Config{
        Storage:   storage,
        SecretKey: "secret",
        // AsyncBackend not set = uses default worker pool
    })

    // Option 2: Custom worker pool
    asyncBackend := events.NewDefaultAsyncBackend(20, 5000, logger)
    authInstance, _ := auth.New(&config.Config{
        Storage:      storage,
        SecretKey:    "secret",
        AsyncBackend: asyncBackend,
    })

    // Option 3: Redis backend
    redisBackend := mybackends.NewRedisBackend("localhost:6379", "goauth:events", logger)
    authInstance, _ := auth.New(&config.Config{
        Storage:      storage,
        SecretKey:    "secret",
        AsyncBackend: redisBackend,
    })

    // Option 4: RabbitMQ backend
    rmqBackend, _ := mybackends.NewRabbitMQBackend(
        "amqp://guest:guest@localhost:5672/",
        "goauth.events",
        logger,
    )
    authInstance, _ := auth.New(&config.Config{
        Storage:      storage,
        SecretKey:    "secret",
        AsyncBackend: rmqBackend,
    })
}
```

## Event Handling

### Sync vs Async Events

```go
// Sync handler - blocks until complete (for rate limiting, validation)
eventBus.Subscribe(events.EventBeforeLogin, func(ctx context.Context, event *events.Event) error {
    // Rate limiting check
    return checkRateLimit(ctx, event)
})

// Async handler - uses backend (for notifications, analytics)
eventBus.Subscribe(events.EventAfterSignup, func(ctx context.Context, event *events.Event) error {
    // Send welcome email
    return sendWelcomeEmail(event)
}, events.WithAsync())
```

### How It Works

1. **Sync Events (`EmitSync`)**: Always execute immediately, regardless of backend
2. **Async Events (`Emit`)**:
   - **Sync handlers**: Execute immediately
   - **Async handlers**:
     - **Default backend**: Submit to worker pool
     - **External queue**: Publish to queue (Redis/RabbitMQ/etc.)

### Important Notes

⚠️ **When using external queues**:
- You need to implement **consumers** that read from the queue and execute handlers
- The `Publish()` method only sends the event to the queue
- Handlers registered with `WithAsync()` won't execute locally when using external queues
- This is by design - external queues are for distributed processing

✅ **Recommended pattern for external queues**:
```go
// In your main auth service
eventBus.Subscribe(events.EventAfterSignup, func(ctx context.Context, event *events.Event) error {
    // This just publishes to Redis/RabbitMQ
    return nil
}, events.WithAsync())

// In your separate worker service
// Read from queue and process events
func worker() {
    for msg := range queue {
        event := parseEvent(msg)
        handleAfterSignup(event) // Your actual logic
    }
}
```

## Benefits

✅ **Flexibility**: Choose the right backend for your infrastructure  
✅ **Scalability**: Scale event processing independently  
✅ **Reliability**: Use battle-tested message queues  
✅ **No Dependencies**: Core library has no external queue dependencies  
✅ **Simple**: Default worker pool works great for most use cases  

## When to Use Each Backend

| Backend | Use Case | Pros | Cons |
|---------|----------|------|------|
| **Worker Pool** | Single instance, moderate load | Simple, no deps, fast | Memory-only, not distributed |
| **Redis** | Multi-instance, high reliability | Persistent, distributed | Requires Redis |
| **RabbitMQ** | Complex routing, high throughput | Feature-rich, reliable | Requires RabbitMQ |
| **Kafka** | High throughput, event sourcing | Scalable, durable | Complex setup |
| **AWS SQS** | AWS infrastructure, serverless | Managed, scalable | AWS lock-in, cost |

## Testing

### Mock Backend for Tests

```go
type MockBackend struct {
    published []events.Event
}

func (m *MockBackend) Publish(ctx context.Context, eventType events.EventType, event *events.Event) error {
    m.published = append(m.published, *event)
    return nil
}

func (m *MockBackend) Close() error { return nil }
func (m *MockBackend) Name() string { return "mock" }

// In tests
mockBackend := &MockBackend{}
eventBus := events.NewEventBusWithBackend(logger, mockBackend)

// ... trigger events ...

// Assert
assert.Len(t, mockBackend.published, 1)
assert.Equal(t, events.EventAfterSignup, mockBackend.published[0].Type)
```

## Summary

1. **Default**: Just works with worker pool
2. **Custom**: Implement 3 methods (`Publish`, `Close`, `Name`)
3. **Pass**: Configure via `config.AsyncBackend`
4. **Done**: Async events route to your backend

No forced dependencies, maximum flexibility! 🚀

