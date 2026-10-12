---
id: performance
title: Performance & Optimization
sidebar_label: Performance
---

# Performance and Optimization

Measure the complete authentication path against your own database and workload. The current implementation favors current-state authorization and conditional persistence over signature-only access validation.

## Authentication Strategies

| Strategy | Work performed by built-in access validation |
| --- | --- |
| Stateless | JWT validation plus current user/version/eligibility lookup; organization checks when selected |
| Session | The same checks plus a live, owned, unexpired session lookup |
| Session with cookie cache | Common online checks still run; additional cookie-cache handling may revalidate/reissue cache data |

Stateless means no server-side session record, not no persistence. Refresh nonces, challenges, users, and optional memberships remain shared state. Cookie-cache mode does not remove the common user/session lookup.

## Bounded Work

`MaxConcurrentRequests` defaults to 128 and bounds built-in route work plus in-process `SignIn`. Saturation fails with HTTP 503 for routes. `Admission` can enforce a shared operation budget across replicas. `MaxRequestBodyBytes` defaults to 1 MiB for wrapped built-in handlers.

These controls do not provide per-IP rate limiting. Host routes and direct `Authenticate` calls need any additional host-level admission policy you require.

## Password and Token Costs

Bcrypt password hashing/verification is deliberately CPU-intensive; `HashSaltLength` defaults to cost 10. Benchmark with the actual policy and concurrent sign-in load. Session refresh secrets are SHA-256 hashed for lookup; stateless refresh records hold JTIs. Both refresh paths require atomic persistence.

## Storage Optimization

Keep indexes and migrations current, size connection pools against database capacity, and measure queries for user/session/membership checks. Custom caches must preserve the revocation and conditional-write semantics their calling paths require. GoAuth does not ship a general-purpose in-memory repository cache decorator.

## Events

The default async backend has ten workers and a queue of 1000. It is in-memory, not a durable message log. Monitor queue pressure and handler latency. With `DurableEvents`, outbox records are delivered by bounded leased batches and may be retried; consumers should be idempotent.

## Measuring

```bash
go test -run '^$' -bench . -benchmem ./internal/security/...
go test -run '^$' -bench . -benchmem ./storage/...
```

These commands run benchmarks that exist in the selected packages; they are not a claim of measured throughput. For application testing, include password sign-in, protected requests, refresh races, database latency, additional-factor flows, and callback delivery. Do not apply latency or complexity claims from older signature-only descriptions to the current implementation.
