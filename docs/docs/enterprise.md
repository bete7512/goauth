---
id: enterprise
title: Enterprise Deployment
sidebar_label: Enterprise
---

# Events and Deployment

Deploy GoAuth inside your application and share the persistence required by the selected modules across replicas. Both Session and Stateless depend on current user state and persisted refresh/continuation records.

## Runtime Lifecycle

Register components and event handlers before initialization. Keep the initialization context alive, drain the host HTTP server on shutdown, then call `Auth.Shutdown(ctx)`. The runtime stops modules in reverse dependency order and closes owned resources. `BorrowStorage` keeps application-owned storage open.

## Pluggable Async Backend

The default backend is an in-memory worker pool with ten workers and a queue of 1000. A custom backend implements:

```go
type AsyncBackend interface {
    Publish(context.Context, types.EventType, *types.Event) error
    Subscribe(context.Context, types.EventDispatcher) error
    Close() error
    Name() string
}
```

Provide it as `config.Config.AsyncBackend`. GoAuth does not include built-in Kafka, NATS, RabbitMQ, or Redis adapters; those are implementations your application can supply. Being asynchronous does not by itself make delivery durable.

Handlers are registered before backend consumption starts. Synchronous hooks can abort their calling operation; async handlers run through the dispatcher and configured retry policies. Authentication factor policy uses `AuthInterceptors` and the shared completer, not a blocking email/event callback.

## Acknowledged Delivery

A durable backend can additionally implement:

```go
type AcknowledgingBackend interface {
    SubscribeAcknowledged(context.Context, func(context.Context, *types.Event) error) error
}
```

Acknowledge only nil processing results. Errors remain retryable. Delivery can repeat, so consumers must deduplicate by stable event ID and handler rather than assume exactly-once effects.

`types.EventEnvelope` is the wire representation: version, ID, type, realm, creation time, and JSON payload. It excludes runtime contexts, errors, and retry bookkeeping. The current decoder accepts version 1 and realm `default`. Decoded payloads are JSON; use `types.EventDataAs` or explicit decoding when supporting both local typed payloads and transported events.

## Transactional Outbox

```go
cfg.DurableEvents = true
```

This requires aggregate `types.TransactionalStorage` and `types.OutboxStore` on the shared storage and inside its transaction callback. The GORM adapter supplies them.

Authentication completion records `authentication.completed` with user ID, session ID, and verified methods in the same transaction as the grant. Security operations routed through the transaction wrapper can also persist their async events with their mutations. This is not a blanket guarantee that every legacy event emission uses the outbox.

The runtime drains once per second in batches of up to 32, with one-minute leases. Handler failure schedules a retry; successful acknowledged dispatch removes the row. Stable IDs survive retry. This outbox dispatches to registered handlers; it does not automatically turn every event into a message on your custom broker.

```go
a.On(types.EventType("authentication.completed"), func(ctx context.Context, event *types.Event) error {
    // Decode event.Data and deduplicate using event.ID before external effects.
    return nil
})
```

## Composition and Storage

Missing module dependencies, capabilities, or middleware cause initialization errors. Invitation and Audit require Admin. OAuth identity mutations and invitation acceptance need colocated transactional feature stores. Durable Core signup/password operations require them as well. See [Storage contracts](storage.md).

`MaxConcurrentRequests`, `MaxRequestBodyBytes`, `Admission`, and `Observer` provide host integration points. No built-in Prometheus exporter, distributed rate limiter, or external broker is implied by these interfaces.

## Organizations and Identity Providers

Organizations provide membership roles `owner`, `admin`, and `member`, with current-state checks. They are not independent identity realms or a general application-permission system. Use [OAuth named connections](modules/oauth.md) for the supported providers; Microsoft pins an explicit tenant. A custom provider is trusted in-process code, not an arbitrary issuer URL submitted by a client.

See [Security](security.md), [Migration management](migrations.md), and [Upgrading](upgrade.md) before changing a running deployment.
