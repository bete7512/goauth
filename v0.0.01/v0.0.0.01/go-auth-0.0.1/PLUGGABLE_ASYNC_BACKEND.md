# Pluggable Async Backend System

## ✅ Completed Implementation

You now have a **fully pluggable async backend system** for event processing!

## 🎯 Key Features

### 1. **Default Behavior (Zero Config)**
```go
auth, _ := auth.New(&config.Config{
    Storage:   storage,
    SecretKey: "secret",
    // No AsyncBackend = uses built-in worker pool
})
```
- ✅ Works immediately with **10 workers, 1000 queue size**
- ✅ No external dependencies
- ✅ Perfect for single-instance deployments

### 2. **Custom External Queue (Redis, RabbitMQ, Kafka, etc.)**
```go
// Implement 3 methods
type MyCustomBackend struct {}

func (b *MyCustomBackend) Publish(ctx context.Context, eventType string, event interface{}) error {
    // Your queue logic here
    return nil
}

func (b *MyCustomBackend) Close() error {
    // Cleanup
    return nil
}

func (b *MyCustomBackend) Name() string {
    return "my-backend"
}

// Use it
auth, _ := auth.New(&config.Config{
    Storage:      storage,
    SecretKey:    "secret",
    AsyncBackend: &MyCustomBackend{},
})
```

## 🔧 Interface

```go
// In pkg/config/config.go
type AsyncBackend interface {
    Publish(ctx context.Context, eventType string, event interface{}) error
    Close() error
    Name() string
}
```

## 📦 What Was Implemented

### Files Created/Modified:

1. **`internal/events/backend.go`**
   - `AsyncBackend` interface
   - `DefaultAsyncBackend` (worker pool wrapper)

2. **`internal/events/events.go`**
   - `NewEventBusWithBackend()` - Create event bus with custom backend
   - `Close()` - Gracefully shutdown
   - Updated `Emit()` to route async events to backend

3. **`pkg/config/config.go`**
   - Added `AsyncBackend` interface
   - Added `AsyncBackend` field to `Config`

4. **`pkg/auth/auth.go`**
   - Auto-detect custom backend from config
   - Adapter to bridge interfaces
   - `Close()` method for cleanup

5. **`internal/events/ASYNC_BACKENDS.md`**
   - Complete documentation
   - Implementation examples (Redis, RabbitMQ, Kafka, SQS)

6. **`examples/custom_async_backend/main.go`**
   - Working examples

## 🚀 Usage Examples

### Default (Built-in Worker Pool)
```go
auth, _ := auth.New(&config.Config{
    Storage:   storage,
    SecretKey: "secret",
})
// That's it! Uses worker pool automatically
```

### Redis Backend
```go
import "github.com/redis/go-redis/v9"

type RedisBackend struct {
    client *redis.Client
}

func (b *RedisBackend) Publish(ctx context.Context, eventType string, event interface{}) error {
    data, _ := json.Marshal(event)
    return b.client.XAdd(ctx, &redis.XAddArgs{
        Stream: "goauth:events",
        Values: map[string]interface{}{
            "type": eventType,
            "data": string(data),
        },
    }).Err()
}

func (b *RedisBackend) Close() error {
    return b.client.Close()
}

func (b *RedisBackend) Name() string {
    return "redis"
}

// Usage
redisBackend := &RedisBackend{
    client: redis.NewClient(&redis.Options{
        Addr: "localhost:6379",
    }),
}

auth, _ := auth.New(&config.Config{
    Storage:      storage,
    SecretKey:    "secret",
    AsyncBackend: redisBackend,
})
```

### RabbitMQ Backend
```go
import amqp "github.com/rabbitmq/amqp091-go"

type RabbitMQBackend struct {
    channel *amqp.Channel
}

func (b *RabbitMQBackend) Publish(ctx context.Context, eventType string, event interface{}) error {
    data, _ := json.Marshal(event)
    return b.channel.PublishWithContext(ctx, "goauth.events", eventType, false, false,
        amqp.Publishing{
            ContentType: "application/json",
            Body:        data,
        },
    )
}

func (b *RabbitMQBackend) Close() error {
    return b.channel.Close()
}

func (b *RabbitMQBackend) Name() string {
    return "rabbitmq"
}

// Usage
conn, _ := amqp.Dial("amqp://guest:guest@localhost:5672/")
ch, _ := conn.Channel()

auth, _ := auth.New(&config.Config{
    Storage:      storage,
    SecretKey:    "secret",
    AsyncBackend: &RabbitMQBackend{channel: ch},
})
```

## 🔄 How It Works

### Event Flow

```
User Action → Service Method → Event Bus
                                   ↓
                          ┌────────┴────────┐
                          │                 │
                    Sync Handlers    Async Handlers
                          │                 │
                    Execute Now       Route to Backend
                                            ↓
                                  ┌─────────┴─────────┐
                                  │                   │
                          Worker Pool           External Queue
                          (Default)             (Redis/RabbitMQ/etc.)
```

### Sync vs Async Events

```go
// Sync event - always executes immediately
eventBus.EmitSync(ctx, "before:login", data)

// Async event with sync handler - executes immediately
eventBus.Subscribe(events.EventAfterSignup, handler)

// Async event with async handler - routes to backend
eventBus.Subscribe(events.EventAfterSignup, handler, events.WithAsync())
```

## ⚡ Benefits

### For Users

✅ **No Lock-in**: Use any queue system you want  
✅ **Zero Config**: Works great without any setup  
✅ **Simple Interface**: Only 3 methods to implement  
✅ **Type Safe**: Full type safety with interfaces  
✅ **Clean Shutdown**: Proper cleanup with `Close()`  

### For Library

✅ **No Dependencies**: Core has no external queue dependencies  
✅ **Flexible**: Users choose what fits their infrastructure  
✅ **Testable**: Easy to mock backends for testing  
✅ **Scalable**: Distributed event processing when needed  

## 📊 Decision Matrix

| Scenario | Recommendation |
|----------|---------------|
| Single instance, < 1000 req/min | **Default worker pool** |
| Multiple instances, shared events | **Redis Streams** |
| Complex routing, high throughput | **RabbitMQ** |
| Event sourcing, huge scale | **Apache Kafka** |
| AWS infrastructure | **AWS SQS/SNS** |
| Testing | **Mock backend** |

## 🧪 Testing

```go
type MockBackend struct {
    Published []string
}

func (m *MockBackend) Publish(ctx context.Context, eventType string, event interface{}) error {
    m.Published = append(m.Published, eventType)
    return nil
}

func (m *MockBackend) Close() error { return nil }
func (m *MockBackend) Name() string { return "mock" }

// In tests
mock := &MockBackend{}
auth, _ := auth.New(&config.Config{
    Storage:      testStorage,
    SecretKey:    "test",
    AsyncBackend: mock,
})

// ... trigger events ...

assert.Equal(t, "after:signup", mock.Published[0])
```

## 🎉 Summary

You now have:

1. ✅ **Interface-based** pluggable system
2. ✅ **Default implementation** (worker pool) that works out of the box
3. ✅ **No forced dependencies** - users bring their own queue clients
4. ✅ **Complete documentation** with examples
5. ✅ **Clean API** - only 3 methods to implement
6. ✅ **Proper cleanup** with Close() method

**Users can:**
- ✅ Use default worker pool (zero config)
- ✅ Implement Redis backend (3 methods)
- ✅ Implement RabbitMQ backend (3 methods)
- ✅ Implement ANY queue system they want
- ✅ Switch backends without changing application code

**No external dependencies forced, maximum flexibility!** 🚀

