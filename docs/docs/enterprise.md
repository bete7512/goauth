---
id: enterprise
title: Enterprise Deployment
sidebar_label: Enterprise
description: Running GoAuth on several replicas. The runtime lifecycle, custom event backends, acknowledged delivery, the transactional outbox, and what is not built in.
---

# Events and Deployment

Running GoAuth on more than one instance, and making sure an event is not lost.

- **All replicas share one database.** Both Session and Stateless read current user state and stored refresh records from it.
- **By default, events are delivered from an in-memory queue.** That needs no setup, but an event waiting in the queue is lost if the process dies. The sections below show how to do better.

## Runtime Lifecycle

1. Register components and event handlers **before** `Initialize`.
2. Keep the context you passed to `Initialize` alive while the application runs.
3. On shutdown, drain your HTTP server first, then call `Auth.Shutdown(ctx)`. It stops modules in reverse dependency order and closes what it owns; with `BorrowStorage`, your storage stays open.

## Pluggable Async Backend

The default backend is an in-memory pool with ten workers and a queue of 1000. To use your own transport, implement:

```go
type AsyncBackend interface {
    Publish(context.Context, types.EventType, *types.Event) error
    Subscribe(context.Context, types.EventDispatcher) error
    Close() error
    Name() string
}
```

Pass it as `config.Config.AsyncBackend`.

- GoAuth ships no Kafka, NATS, RabbitMQ or Redis backend; [`examples/nats_backend.go`](https://github.com/bete7512/goauth/blob/main/examples/nats_backend.go) is a NATS JetStream example to start from.
- Asynchronous does not mean durable. That depends on the backend.
- Synchronous hooks can abort the operation that called them. Async handlers run through the dispatcher with the configured retry policy.
- Second-factor policy does not use events. It goes through `AuthInterceptors` and the shared sign-in path.

## Acknowledged Delivery

A durable backend can also implement:

```go
type AcknowledgingBackend interface {
    SubscribeAcknowledged(context.Context, func(context.Context, *types.Event) error) error
}
```

Acknowledge only when the handler returned nil; an error leaves the event eligible for retry. An event can arrive more than once, so deduplicate by event ID and do not assume exactly-once.

**On the wire.** `types.EventEnvelope` carries version, ID, type, realm, creation time and a JSON payload, without runtime context, errors or retry bookkeeping. The decoder accepts version 1 and realm `default`. Decoded payloads are JSON, so use `types.EventDataAs` or decode explicitly when a handler receives both local typed payloads and transported events.

## Transactional Outbox

The outbox closes the gap between "the change was saved" and "the event was sent": the event is written in the same transaction as the change and delivered afterwards.

```go
cfg.DurableEvents = true
```

It requires `types.TransactionalStorage` and `types.OutboxStore`, including inside the transaction callback. The bundled GORM storage has both.

**What it covers.**

- A completed sign-in records `authentication.completed`, with the user ID, session ID and verified methods, in the same transaction as the grant.
- Security operations that run through the transaction wrapper store their async events with their changes.
- It is **not** a guarantee that every older event emission goes through the outbox.

**How it delivers.**

- The runtime drains once per second, in batches of up to 32, with one-minute leases.
- A handler failure schedules a retry; a successful dispatch removes the row. The event ID is the same across retries.
- The outbox dispatches to registered handlers. It does not publish every event to your custom broker.

```go
a.On(types.EventType("authentication.completed"), func(ctx context.Context, event *types.Event) error {
    // Decode event.Data and deduplicate using event.ID before external effects.
    return nil
})
```

## Composition and Storage

- Missing module dependencies, capabilities or middleware make `Initialize` fail. Invitation and Audit need Admin.
- OAuth identity changes and invitation acceptance need feature stores that share one transaction, and so do Core sign-up and password operations with `DurableEvents`. See [Storage](storage.md).
- `MaxConcurrentRequests`, `MaxRequestBodyBytes`, `Admission` and `Observer` are places to plug your own systems in. GoAuth ships no Prometheus exporter and no message broker, and the rate limiter counts per process unless you give it a shared store; see [Rate Limit](modules/ratelimit.md).

## Organizations and Identity Providers

- Organizations give users the roles `owner`, `admin` and `member`, checked against current state. They are not separate identity realms; for permissions on your own resources, use the [RBAC module](modules/rbac.md).
- Use [OAuth named connections](modules/oauth.md) for the supported providers. Microsoft is pinned to an explicit tenant.
- A custom OAuth provider is code you compile in and trust, never an issuer URL a client submits.

Before changing a running deployment, read [Security](security.md), [Migrations](migrations.md) and [Upgrading](upgrade.md).
