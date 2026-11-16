---
id: performance
title: Performance & Optimization
sidebar_label: Performance
description: What each GoAuth request costs, the built-in limits, and how to measure sign-in, refresh and protected requests against your own database.
---

# Performance and Optimization

GoAuth checks the database on every protected request, on purpose: that is what makes a ban or a password change take effect immediately. So plan for database round trips, plus bcrypt when someone signs in, and measure with your own database and traffic.

## What a protected request costs

| Strategy | Work performed by built-in access validation |
| --- | --- |
| Stateless | JWT validation plus current user/version/eligibility lookup; organization checks when selected |
| Session | The same checks plus a live, owned, unexpired session lookup |
| Session with cookie cache | Common online checks still run; additional cookie-cache handling may revalidate/reissue cache data |

"Stateless" means no session row, not no database: refresh records, pending challenges, users and memberships are still shared state. The cookie cache does not remove the user and session lookup either.

## Built-in limits

- `MaxConcurrentRequests` (default 128) bounds built-in routes and in-process `SignIn`. When full, routes answer HTTP 503.
- `Admission` enforces one budget across replicas.
- `MaxRequestBodyBytes` (default 1 MiB) applies to the built-in handlers.

These are capacity limits, not per-client rate limits; the [Rate Limit module](modules/ratelimit.md) does that. Your own routes and direct `Authenticate` calls are not covered.

## Passwords and tokens

- **bcrypt is slow on purpose.** The cost comes from `HashSaltLength` (default 10). Benchmark sign-in with your policy and the concurrency you expect.
- Session refresh secrets are hashed with SHA-256 for lookup; stateless refresh records hold token IDs. Both paths need an atomic write.

## The database

- Keep indexes and migrations current, and size connection pools to what the database can handle.
- Measure the queries that check users, sessions and memberships.
- A cache of your own must keep the revocation and conditional-write behavior the calling code relies on. GoAuth ships no general repository cache.

## Events

The default backend has ten workers and a queue of 1000, in memory. Watch queue pressure and handler latency. With `DurableEvents`, outbox rows are delivered in bounded, leased batches and can be retried, so handlers should be safe to run twice.

## Measuring

```bash
go test -run '^$' -bench . -benchmem ./internal/security/...
go test -run '^$' -bench . -benchmem ./storage/...
```

These run the benchmarks in those packages; they are not a throughput claim. For your application, test what real traffic does: password sign-in, protected requests, two refreshes racing, a slow database, second-factor flows and callback delivery. Numbers for systems that only verify a signature do not apply.
