---
slug: goauth-performance-benchmarks
title: "GoAuth Performance: Architecture and Benchmarking"
authors: [goauth-team]
tags: [performance, benchmarks, go, authentication]
---

# GoAuth Performance: Architecture and Benchmarking

Authentication performance depends on password hashing, storage latency, concurrency, and event delivery. This article is updated for the current checkout and makes no claim of measured throughput or database-free built-in authentication.

<!-- truncate -->

## Authentication strategy costs

| Strategy | Work on the protected-request path |
|---|---|
| Stateless | Verify JWT and purpose; check current user, token version, and selected organization |
| Session | The same checks plus current session ownership and expiry |
| Session with cookie cache | Cache parsing and periodic cache maintenance, while current user/session validation still applies |

Choose a strategy based on credential lifecycle and revocation needs. The name Stateless describes the access credential format; refresh nonces and user state still live in storage. Cookie caching does not bypass the current-state checks in the built-in authentication middleware.

## Password hashing

Bcrypt is intentionally expensive. The default cost is 10, configured by `Security.HashSaltLength`. Measure signup, successful and unsuccessful password login, and concurrent workloads separately. A signature-only JWT microbenchmark does not measure the complete protected-request path.

Session refresh hashes opaque secrets with SHA-256. Stateless refresh verifies a JWT and atomically replaces its stored nonce. Both have storage work and contention to include in a benchmark.

## Bounded work and asynchronous events

The runtime defaults to 128 concurrent requests and a 1 MiB request-body limit. Admission rejects work when capacity is exhausted instead of waiting in an unlimited queue. Host routes wrapped only with `RequireAuth` do not automatically inherit every route-level limit.

The default event backend has 10 workers and a 1,000-item queue. External backends and durable outbox delivery have different latency and failure characteristics. Measure queue saturation, retries, and slow notification or audit handlers as well as HTTP latency.

## Storage and migrations

The GORM store supplies repositories for PostgreSQL, MySQL, and SQLite. Tune connection pools for your database and workload. GoAuth does not ship a general in-memory storage cache decorator. Custom stores must preserve atomic consumption and refresh rotation; caching must not weaken current-state checks.

Run schema migration separately from load measurement. Startup lock acquisition, dirty-state checks, and migration SQL should not be mistaken for steady-state request cost.

## Running benchmarks

```bash
go test -bench=. -benchmem ./internal/security/...
go test -bench=. -benchmem ./storage/...
```

These commands run any benchmarks present in the selected packages. Add representative end-to-end measurements for your deployment: latency percentiles, error rates, CPU, memory, query counts, pool waits, and event backlog. Include simultaneous refresh attempts and revoked or expired credentials.

The [Performance guide](/docs/performance) explains the request path. [Enterprise deployment](/docs/enterprise) covers admission, observation, and durable events.
