---
slug: goauth-performance-benchmarks
title: "GoAuth Performance: Architecture and Benchmarking"
authors: [goauth-team]
tags: [performance, benchmarks, go, authentication]
---

# GoAuth Performance: Architecture and Benchmarking

Performance in an authentication library comes down to how often you hit the database, how you handle concurrent work, and what you do with CPU-intensive operations like password hashing. This post covers the architectural choices in GoAuth that affect performance and how to benchmark them yourself.

<!-- truncate -->

## Authentication Strategy Performance

The single biggest performance decision in GoAuth is choosing between session and stateless authentication:

| Strategy | Validation Cost | Best For |
|----------|----------------|----------|
| **Stateless (JWT)** | O(1) -- HMAC verification, no DB call | High-traffic APIs, microservices |
| **Session (DB)** | O(log N) -- DB lookup per request | High-security apps where immediate revocation matters |
| **Session (Cookie-Cache)** | O(1) most requests, periodic DB sync | Balanced apps needing revocation without constant DB load |

### Cookie-Cache Strategy

The session module's cookie-cache strategy is the most interesting from a performance perspective. It works by:

1. On login, the session is stored in the database and a session cookie is set.
2. A short-lived cache cookie (configurable TTL, e.g., 5 minutes) is set alongside the session cookie.
3. On subsequent requests, if the cache cookie is still valid, the session is trusted without a database round-trip.
4. When the cache cookie expires, the next request checks the database and refreshes the cache.

This gives you near-stateless performance for the common case while keeping the ability to revoke sessions within the cache TTL window.

```go
a.Use(session.New(&config.SessionModuleConfig{
    Strategy:       types.SessionStrategyCookieCache,
    CookieCacheTTL: 5 * time.Minute,
}, nil))
```

## Password Hashing

GoAuth uses **bcrypt** for password hashing. Bcrypt is deliberately slow -- that is the point. The cost factor controls how many rounds of hashing are performed:

- Default cost: 10 (standard `bcrypt.DefaultCost`)
- Each increment roughly doubles the time

This is the most CPU-intensive operation in the auth lifecycle. For most applications, the default cost is appropriate. If you are seeing login latency issues under load, the bottleneck is almost certainly bcrypt, which is by design -- it prevents brute-force attacks.

## Refresh Token Hashing

Refresh tokens are hashed with **SHA-256** before storage. This is a fast, constant-time operation that adds negligible overhead but ensures that a database breach does not expose raw refresh tokens.

## Async Event Processing

GoAuth's event system uses a **worker pool** (default: 10 workers, 1000-item queue) for asynchronous event processing. Events like sending notification emails or writing audit logs are dispatched to the pool without blocking the HTTP response.

The worker pool is the default `AsyncBackend`. You can replace it with a custom implementation (e.g., backed by a message queue) by implementing the `types.AsyncBackend` interface.

For synchronous intercept points (like checking 2FA during login), GoAuth uses `EmitSync`, which blocks and returns errors to the caller.

## Storage Optimization

GoAuth's GORM-based storage includes several optimizations:

- **Selective migrations**: Each module only migrates the tables it needs.
- **Indexed lookups**: Core tables have indexes on email and username for fast authentication queries.
- **Type-safe storage access**: `Storage.Core()`, `Storage.Session()`, `Storage.Stateless()` -- no reflection or string-based lookups.
- **In-memory cache decorator**: An optional cache layer that can be wrapped around any storage implementation.

## Running Benchmarks

GoAuth includes benchmarks in the test suite. Run them yourself to see performance on your hardware:

```bash
make test-bench
```

This runs Go's standard `testing.B` benchmarks across the codebase. Results will vary based on your CPU, memory, and disk speed. Do not trust benchmark numbers from blog posts (including this one) -- always measure on your own infrastructure.

You can also run benchmarks for specific packages:

```bash
go test -bench=. -benchmem ./internal/security/...
go test -bench=. -benchmem ./storage/...
```

## Practical Recommendations

1. **Use stateless auth by default.** It eliminates database calls for token validation entirely.
2. **If you need session revocation**, use the cookie-cache strategy with a reasonable TTL (2-5 minutes) rather than checking the database on every request.
3. **Keep access token TTL short** (15 minutes default). Short-lived tokens reduce the window of exposure without requiring token blacklisting.
4. **Offload heavy work to the event system.** Email sending, audit logging, and webhook delivery all happen asynchronously by default.
5. **Index your database.** GoAuth's auto-migration creates indexes, but verify they exist if you manage migrations manually.

---

_See the [Performance docs](/docs/performance) for strategy comparison details, and the [Session Module](/docs/modules/session) docs for cookie-cache configuration._
