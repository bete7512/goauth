# Async Event Backends

## Overview

The event system supports **pluggable async backends** for event processing. The backend acts as the transport layer between `EmitAsync` and handler execution — replacing the default in-memory worker pool with a durable queue (NATS, Redis, RabbitMQ, etc.) when needed.

Key principle: **the backend handles both publishing and consuming**. Developers register handlers via `auth.On()` and the backend takes care of queuing and delivery. No separate consumer implementation required.

1. ✅ Use the **default worker pool** (built-in, no external dependencies)
2. ✅ Implement your own backend (NATS JetStream, Redis Streams, Kafka, etc.)

## AsyncBackend Interface

```go
type EventDispatcher func(ctx context.Context, event *Event)

type AsyncBackend interface {
    // Publish sends an event to the backend for later processing.
    // Called once per event by EventBus.EmitAsync.
    Publish(ctx context.Context, eventType EventType, event *Event) error

    // Subscribe registers the dispatcher and starts consuming events.
    // The backend must call dispatcher(ctx, event) for each event it receives.
    // Called once by EventBus.Start() after all handlers are registered.
    Subscribe(ctx context.Context, dispatcher EventDispatcher) error

    // Close gracefully shuts down the backend
    Close() error

    // Name returns the backend name for logging
    Name() string
}
```

### How It Works

```
EmitAsync("after:signup", data)
  → EventBus builds Event{ID, Type, Data, CreatedAt}
  → backend.Publish(ctx, eventType, event)
  → return (non-blocking)

Backend consumer picks up event
  → calls dispatcher(ctx, event)
  → dispatcher iterates handlers in priority order
  → executes each handler (with per-handler retry if configured)
```

The `EventDispatcher` is set by `EventBus.Start()`, which is called at the end of `auth.Initialize()` — after all modules register their hooks. This ordering is critical for durable backends: messages replayed on restart are dispatched to already-registered handlers.

## Default Backend (Worker Pool)

**No configuration needed** - works out of the box with an in-memory worker pool.

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

The worker pool is bounded — if the queue is full, events go to the dead-letter queue. Use a custom backend for unlimited/durable queuing.

## Custom Backend Implementation

### Example: Redis Streams

```go
type RedisBackend struct {
    client     *redis.Client
    stream     string
    dispatcher types.EventDispatcher
    cancel     context.CancelFunc
}

func (b *RedisBackend) Publish(ctx context.Context, eventType types.EventType, event *types.Event) error {
    data, _ := json.Marshal(event)
    return b.client.XAdd(ctx, &redis.XAddArgs{
        Stream: b.stream,
        Values: map[string]interface{}{"event": string(data)},
    }).Err()
}

func (b *RedisBackend) Subscribe(ctx context.Context, dispatcher types.EventDispatcher) error {
    b.dispatcher = dispatcher
    consumerCtx, cancel := context.WithCancel(ctx)
    b.cancel = cancel

    // Start consuming in background
    go func() {
        for {
            select {
            case <-consumerCtx.Done():
                return
            default:
                msgs, _ := b.client.XRead(consumerCtx, &redis.XReadArgs{
                    Streams: []string{b.stream, "$"},
                    Block:   5 * time.Second,
                }).Result()
                for _, stream := range msgs {
                    for _, msg := range stream.Messages {
                        var event types.Event
                        json.Unmarshal([]byte(msg.Values["event"].(string)), &event)
                        // Data will be json.RawMessage — EventDataAs[T]() handles unmarshal
                        dispatcher(consumerCtx, &event)
                    }
                }
            }
        }
    }()
    return nil
}

func (b *RedisBackend) Close() error {
    if b.cancel != nil {
        b.cancel()
    }
    return b.client.Close()
}

func (b *RedisBackend) Name() string { return "redis-streams" }
```

### Example: NATS JetStream

See [examples/nats_backend.go](../../examples/nats_backend.go) for a full implementation with:
- Durable message storage (events survive process restarts)
- Server-side deduplication via `Nats-Msg-Id` header
- At-least-once delivery with consumer acknowledgment
- Authentication support (username/password, token, NKey, credentials file)

## Configuration in Auth Package

```go
package main

import (
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
)

func main() {
    // Option 1: Default worker pool (no config needed)
    authInstance, _ := auth.New(&config.Config{
        Storage:   storage,
        SecretKey: "secret",
        // AsyncBackend not set = uses default worker pool
    })

    // Option 2: NATS JetStream backend
    natsBackend, _ := NewNATSJetStreamBackend(ctx, &NATSConfig{
        URL:      "nats://localhost:4222",
        Username: "user",
        Password: "pass",
    })
    authInstance, _ := auth.New(&config.Config{
        Storage:      storage,
        SecretKey:    "secret",
        AsyncBackend: natsBackend,
    })

    // Initialize starts the backend consumer after all hooks are registered
    authInstance.Initialize(ctx)
}
```

## Event Data Serialization

When events pass through a serialized backend (NATS, Redis, etc.), `Event.Data` arrives as `json.RawMessage` instead of the original typed struct. The `types.EventDataAs[T]()` generic function handles this transparently:

```go
// Works with both in-memory (typed struct) and serialized (json.RawMessage) data
data, ok := types.EventDataAs[*types.UserEventData](event)
if !ok {
    return fmt.Errorf("unexpected event data type")
}
fmt.Println(data.UserID)
```

## Event Handling

### Sync vs Async Events

```go
// Sync handler - blocks until complete (for validation, rate limiting)
eventBus.Subscribe(types.EventBeforeLogin, func(ctx context.Context, event *types.Event) error {
    return checkRateLimit(ctx, event)
})

// Async handler - uses backend (for notifications, analytics)
// Handlers registered normally — the backend determines if processing is async
eventBus.Subscribe(types.EventAfterSignup, func(ctx context.Context, event *types.Event) error {
    return sendWelcomeEmail(event)
})
```

### Sync vs Async Emit

1. **`EmitSync`**: Executes all handlers immediately in the calling goroutine
2. **`EmitAsync`**: Publishes to the backend → backend consumer calls dispatcher → dispatcher executes all handlers

Both paths execute the same handlers. The difference is only in the transport: `EmitSync` is inline, `EmitAsync` goes through the backend queue.

## Benefits

✅ **Zero consumer code**: Backend handles both publish and consume internally
✅ **Drop-in replacement**: Swap worker pool for NATS/Redis with no handler changes
✅ **Durability**: Events survive process restarts with durable backends
✅ **Unlimited queue**: No in-memory queue size limits with external backends
✅ **No dependencies**: Core library has no external queue dependencies
✅ **Simple**: Default worker pool works great for most use cases

## When to Use Each Backend

| Backend | Use Case | Pros | Cons |
|---------|----------|------|------|
| **Worker Pool** | Single instance, moderate load | Simple, no deps, fast | Memory-only, bounded queue |
| **NATS JetStream** | Multi-instance, high reliability | Durable, dedup, scalable | Requires NATS |
| **Redis Streams** | Multi-instance, existing Redis | Persistent, distributed | Requires Redis |
| **Kafka** | High throughput, event sourcing | Scalable, durable | Complex setup |

## Testing

### Mock Backend for Tests

```go
type MockBackend struct {
    events     []*types.Event
    dispatcher types.EventDispatcher
}

func (m *MockBackend) Publish(ctx context.Context, eventType types.EventType, event *types.Event) error {
    m.events = append(m.events, event)
    // Optionally dispatch immediately for synchronous test behavior:
    if m.dispatcher != nil {
        m.dispatcher(ctx, event)
    }
    return nil
}

func (m *MockBackend) Subscribe(_ context.Context, dispatcher types.EventDispatcher) error {
    m.dispatcher = dispatcher
    return nil
}

func (m *MockBackend) Close() error { return nil }
func (m *MockBackend) Name() string { return "mock" }
```

## Summary

1. **Default**: Just works with worker pool (10 workers, 1000 queue)
2. **Custom**: Implement 4 methods (`Publish`, `Subscribe`, `Close`, `Name`)
3. **Pass**: Configure via `config.AsyncBackend`
4. **Done**: Backend handles publish + consume, handlers execute via dispatcher
