---
id: enterprise
title: Enterprise Deployment
sidebar_label: Enterprise
---

# Enterprise Deployment

GoAuth is designed to scale from single-instance startups to high-availability enterprise environments.

## Scalability

- **Stateless Authentication**: Default JWT-based [Stateless Module](modules/stateless.md) allows your API nodes to scale horizontally without shared state.
- **Database Pooling**: Leverages GORM's built-in connection pooling for efficient shared database access.
- **Async Processing**: The default in-memory worker pool (10 workers, 1000 event queue) handles emails and events without blocking request threads. For production environments that require message durability, distributed processing, or external monitoring, implement the `types.AsyncBackend` interface to use an external message broker.

## Security & Governance

- **Admin Module**: Dedicated [Admin Module](modules/admin.md) for managing large user bases with role-based access controls.
- **Audit Module**: Comprehensive [Audit Module](modules/audit.md) with per-action retention policies, background cleanup, user self-service activity logs, and admin-facing audit trail.
- **OAuth / SSO**: Integrate with enterprise identity providers (Google Workspace, Microsoft Azure AD) using the [OAuth Module](modules/oauth.md).
- **Two-Factor Authentication**: TOTP-based [Two-Factor Module](modules/twofactor.md) with backup codes, code reuse prevention, and optional enforcement for all users.
- **CSRF & Captcha**: Protect your public signup and login endpoints from automated attacks.
- **Account Lockout**: Configurable failed login attempt tracking with automatic lockout (default: 5 attempts, 15-minute lockout).

## Customizability

- **Framework Agnostic**: Deploy with `net/http`, Gin, Fiber, or Chi using standard adapters.
- **Storage Abstraction**: Implement `types.Storage` to use existing enterprise data stores or non-SQL backends. Every module that uses storage accepts an optional custom storage parameter in its constructor.
- **Event-Driven**: Hook into any lifecycle event to trigger external workflows (e.g., syncing users to CRM). Events support before hooks (sync, abort on error) and after hooks (async, all run). Priority ordering and retry policies per handler.
- **Pluggable Notifications**: Implement `EmailSender` or `SMSSender` interfaces to integrate any email or SMS provider. Built-in: SendGrid, SMTP, Resend (email), Twilio (SMS).

## Pluggable Async Backend

The event system uses a pluggable async backend for processing events. The default in-memory worker pool is suitable for single-instance deployments. For distributed or high-availability environments, implement the `types.AsyncBackend` interface:

```go
type AsyncBackend interface {
    // Publish sends an event to the backend for async processing.
    Publish(ctx context.Context, eventType EventType, event *Event) error

    // Subscribe registers the event dispatcher to receive events from the backend.
    Subscribe(ctx context.Context, dispatcher EventDispatcher) error

    // Close shuts down the backend gracefully.
    Close() error

    // Name returns a human-readable name for the backend (e.g., "kafka", "nats").
    Name() string
}
```

Use this to replace the in-memory worker pool with:
- **Kafka** -- for high-throughput event streaming with durable message logs
- **NATS** -- for lightweight, low-latency pub/sub
- **Redis Streams** -- for Redis-based event queuing with consumer groups
- **RabbitMQ** -- for traditional message broker patterns with routing and acknowledgment

Pass your implementation when creating the auth instance:

```go
a, _ := auth.New(&config.Config{
    AsyncBackend: myKafkaBackend, // implements types.AsyncBackend
    // ...
})
```
