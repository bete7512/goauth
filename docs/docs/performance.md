---
id: performance
title: Performance & Optimization
sidebar_label: Performance
---

# Performance & Optimization

GoAuth is built for low-latency Go applications. Performance characteristics depend primarily on your chosen authentication strategy and storage backend.

## Authentication Strategies

| Strategy | Performance Characteristic | Best For |
|----------|----------------------------|----------|
| **Stateless (JWT)** | O(1) validation. No DB round-trip. | High-traffic public APIs, Microservices. |
| **Session (DB)** | O(log N) validation. Requires DB check every request. | Internal tools, High-security banking. |
| **Session (Cache)** | O(1) validation. Trust-but-verify with periodic DB sync. | Balanced web applications. |

## Storage Optimization

- **Typed Dialects**: GoAuth uses native database drivers via GORM for the best performance on PostgreSQL, MySQL, and SQLite.
- **Selective Migrations**: Modules only migrate the tables they need.
- **Indexing**: Core tables come with optimized indexes for email and username lookups.

## Best Practices

1. **Use Stateless by Default**: Reduces database load significantly.
2. **Configure UpdateAge**: For session-based auth, use `UpdateAge` to prevent constant database updates on every request.
3. **Enable Async Events**: Offload notification sending to background workers.
4. **Use GORM Storage**: The factory implementation is optimized for the most common SQL backends.
