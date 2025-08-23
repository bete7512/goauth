---
id: rate-limiting
title: Rate Limiting
sidebar_label: Rate Limiting
sidebar_position: 4
---

# Rate Limiting

GoAuth provides comprehensive rate limiting capabilities to protect your authentication endpoints from abuse and brute force attacks.

## Overview

Rate limiting helps prevent:

- Brute force attacks on login endpoints
- OAuth abuse and spam
- API endpoint abuse
- DDoS attacks
- Resource exhaustion

## Rate Limiting Strategies

### 1. Fixed Window Rate Limiting

Simple time-based window approach:

```go
type FixedWindowLimiter struct {
    requests map[string]int
    window   time.Duration
    limit    int
    mutex    sync.RWMutex
}

func NewFixedWindowLimiter(window time.Duration, limit int) *FixedWindowLimiter {
    limiter := &FixedWindowLimiter{
        requests: make(map[string]int),
        window:   window,
        limit:    limit,
    }

    // Clean up expired windows
    go limiter.cleanup()

    return limiter
}

func (l *FixedWindowLimiter) Allow(key string) bool {
    l.mutex.Lock()
    defer l.mutex.Unlock()

    if count, exists := l.requests[key]; exists && count >= l.limit {
        return false
    }

    l.requests[key]++
    return true
}

func (l *FixedWindowLimiter) cleanup() {
    ticker := time.NewTicker(l.window)
    for range ticker.C {
        l.mutex.Lock()
        l.requests = make(map[string]int)
        l.mutex.Unlock()
    }
}
```

### 2. Sliding Window Rate Limiting

More accurate rate limiting with overlapping windows:

```go
type SlidingWindowLimiter struct {
    requests map[string][]time.Time
    window   time.Duration
    limit    int
    mutex    sync.RWMutex
}

func NewSlidingWindowLimiter(window time.Duration, limit int) *SlidingWindowLimiter {
    return &SlidingWindowLimiter{
        requests: make(map[string][]time.Time),
        window:   window,
        limit:    limit,
    }
}

func (l *SlidingWindowLimiter) Allow(key string) bool {
    l.mutex.Lock()
    defer l.mutex.Unlock()

    now := time.Now()
    cutoff := now.Add(-l.window)

    // Remove expired timestamps
    if timestamps, exists := l.requests[key]; exists {
        var valid []time.Time
        for _, ts := range timestamps {
            if ts.After(cutoff) {
                valid = append(valid, ts)
            }
        }
        l.requests[key] = valid

        if len(valid) >= l.limit {
            return false
        }
    }

    // Add current request
    l.requests[key] = append(l.requests[key], now)
    return true
}
```

### 3. Token Bucket Rate Limiting

Burst-friendly rate limiting:

```go
type TokenBucketLimiter struct {
    buckets map[string]*TokenBucket
    rate    float64
    capacity int
    mutex   sync.RWMutex
}

type TokenBucket struct {
    tokens    float64
    lastRefill time.Time
    rate       float64
    capacity   int
}

func NewTokenBucketLimiter(rate float64, capacity int) *TokenBucketLimiter {
    return &TokenBucketLimiter{
        buckets:  make(map[string]*TokenBucket),
        rate:     rate,
        capacity: capacity,
    }
}

func (l *TokenBucketLimiter) Allow(key string) bool {
    l.mutex.Lock()
    defer l.mutex.Unlock()

    bucket, exists := l.buckets[key]
    if !exists {
        bucket = &TokenBucket{
            tokens:    float64(l.capacity),
            lastRefill: time.Now(),
            rate:       l.rate,
            capacity:   l.capacity,
        }
        l.buckets[key] = bucket
    }

    // Refill tokens
    now := time.Now()
    elapsed := now.Sub(bucket.lastRefill).Seconds()
    bucket.tokens = math.Min(float64(l.capacity), bucket.tokens+elapsed*bucket.rate)
    bucket.lastRefill = now

    if bucket.tokens >= 1 {
        bucket.tokens--
        return true
    }

    return false
}
```

## Implementation in GoAuth

### 1. Rate Limiting Middleware

```go
// Rate limiting middleware
func RateLimitMiddleware(limiter interfaces.RateLimiter, keyFunc func(c *gin.Context) string) gin.HandlerFunc {
    return func(c *gin.Context) {
        key := keyFunc(c)

        if !limiter.Allow(key) {
            c.JSON(429, gin.H{
                "error": "Rate limit exceeded",
                "retry_after": limiter.GetRetryAfter(key),
            })
            c.Abort()
            return
        }

        // Add rate limit headers
        c.Header("X-RateLimit-Limit", strconv.Itoa(limiter.GetLimit()))
        c.Header("X-RateLimit-Remaining", strconv.Itoa(limiter.GetRemaining(key)))
        c.Header("X-RateLimit-Reset", strconv.FormatInt(limiter.GetResetTime(key), 10))

        c.Next()
    }
}
```

### 2. Key Generation Strategies

```go
// IP-based rate limiting
func IPKeyFunc(c *gin.Context) string {
    return c.ClientIP()
}

// User-based rate limiting
func UserKeyFunc(c *gin.Context) string {
    if userID, exists := c.Get("user_id"); exists {
        return fmt.Sprintf("user:%s", userID)
    }
    return c.ClientIP()
}

// Endpoint-based rate limiting
func EndpointKeyFunc(c *gin.Context) string {
    return fmt.Sprintf("%s:%s", c.ClientIP(), c.FullPath())
}

// Combined key strategy
func CombinedKeyFunc(c *gin.Context) string {
    userID := "anonymous"
    if uid, exists := c.Get("user_id"); exists {
        userID = uid.(string)
    }

    return fmt.Sprintf("%s:%s:%s", userID, c.ClientIP(), c.FullPath())
}
```

## Configuration

### Rate Limiting Configuration

```go
cfg := &config.Config{
    Security: config.SecurityConfig{
        RateLimiting: config.RateLimitingConfig{
            Enabled: true,
            Strategy: "sliding_window", // "fixed_window", "sliding_window", "token_bucket"
            Default: config.RateLimit{
                Window:  1 * time.Minute,
                Limit:   100,
                Burst:   10,
            },
            Endpoints: map[string]config.RateLimit{
                "/api/auth/login": {
                    Window:  1 * time.Minute,
                    Limit:   5,
                    Burst:   1,
                },
                "/api/auth/register": {
                    Window:  1 * time.Hour,
                    Limit:   3,
                    Burst:   1,
                },
                "/api/auth/forgot-password": {
                    Window:  1 * time.Hour,
                    Limit:   3,
                    Burst:   1,
                },
                "/api/auth/2fa/verify": {
                    Window:  1 * time.Minute,
                    Limit:   3,
                    Burst:   1,
                },
                "/api/oauth/*": {
                    Window:  1 * time.Minute,
                    Limit:   10,
                    Burst:   2,
                },
            },
        },
    },
}
```

### Environment Variables

```bash
# Rate limiting configuration
RATE_LIMITING_ENABLED=true
RATE_LIMITING_STRATEGY=sliding_window
RATE_LIMITING_DEFAULT_WINDOW=1m
RATE_LIMITING_DEFAULT_LIMIT=100
RATE_LIMITING_DEFAULT_BURST=10

# Login endpoint rate limiting
RATE_LIMITING_LOGIN_WINDOW=1m
RATE_LIMITING_LOGIN_LIMIT=5
RATE_LIMITING_LOGIN_BURST=1

# Registration endpoint rate limiting
RATE_LIMITING_REGISTER_WINDOW=1h
RATE_LIMITING_REGISTER_LIMIT=3
RATE_LIMITING_REGISTER_BURST=1
```

## Endpoint-Specific Rate Limiting

### 1. Authentication Endpoints

```go
// Login rate limiting
func setupLoginRateLimiting(r *gin.RouterGroup) {
    loginLimiter := rate.NewLimiter(rate.Every(1*time.Minute), 5) // 5 per minute

    r.POST("/login", RateLimitMiddleware(loginLimiter, IPKeyFunc), loginHandler)
}

// Registration rate limiting
func setupRegistrationRateLimiting(r *gin.RouterGroup) {
    registerLimiter := rate.NewLimiter(rate.Every(1*time.Hour), 3) // 3 per hour

    r.POST("/register", RateLimitMiddleware(registerLimiter, IPKeyFunc), registerHandler)
}

// Password reset rate limiting
func setupPasswordResetRateLimiting(r *gin.RouterGroup) {
    resetLimiter := rate.NewLimiter(rate.Every(1*time.Hour), 3) // 3 per hour

    r.POST("/forgot-password", RateLimitMiddleware(resetLimiter, IPKeyFunc), forgotPasswordHandler)
    r.POST("/reset-password", RateLimitMiddleware(resetLimiter, IPKeyFunc), resetPasswordHandler)
}
```

### 2. OAuth Endpoints

```go
// OAuth rate limiting
func setupOAuthRateLimiting(r *gin.RouterGroup) {
    oauthLimiter := rate.NewLimiter(rate.Every(1*time.Minute), 10) // 10 per minute

    r.GET("/oauth/:provider", RateLimitMiddleware(oauthLimiter, IPKeyFunc), initiateOAuth)
    r.GET("/oauth/:provider/callback", RateLimitMiddleware(oauthLimiter, IPKeyFunc), oauthCallback)
}
```

### 3. 2FA Endpoints

```go
// 2FA rate limiting
func setup2FARateLimiting(r *gin.RouterGroup) {
    twoFALimiter := rate.NewLimiter(rate.Every(1*time.Minute), 3) // 3 per minute

    r.POST("/2fa/enable", RateLimitMiddleware(twoFALimiter, UserKeyFunc), enable2FA)
    r.POST("/2fa/verify", RateLimitMiddleware(twoFALimiter, UserKeyFunc), verify2FA)
    r.POST("/2fa/disable", RateLimitMiddleware(twoFALimiter, UserKeyFunc), disable2FA)
}
```

## Storage Backends

### 1. In-Memory Storage

```go
// In-memory rate limiter
type InMemoryRateLimiter struct {
    limiters map[string]interfaces.RateLimiter
    mutex    sync.RWMutex
}

func NewInMemoryRateLimiter() *InMemoryRateLimiter {
    return &InMemoryRateLimiter{
        limiters: make(map[string]interfaces.RateLimiter),
    }
}

func (l *InMemoryRateLimiter) GetLimiter(key string) interfaces.RateLimiter {
    l.mutex.Lock()
    defer l.mutex.Unlock()

    if limiter, exists := l.limiters[key]; exists {
        return limiter
    }

    // Create new limiter for key
    limiter := NewSlidingWindowLimiter(1*time.Minute, 100)
    l.limiters[key] = limiter

    return limiter
}
```

### 2. Redis Storage

```go
// Redis-based rate limiter
type RedisRateLimiter struct {
    client *redis.Client
    prefix string
}

func NewRedisRateLimiter(client *redis.Client) *RedisRateLimiter {
    return &RedisRateLimiter{
        client: client,
        prefix: "rate_limit:",
    }
}

func (l *RedisRateLimiter) Allow(key string) bool {
    fullKey := l.prefix + key
    now := time.Now().Unix()

    // Use Redis sorted set for sliding window
    pipe := l.client.Pipeline()
    pipe.ZRemRangeByScore(fullKey, "0", strconv.FormatInt(now-60, 10)) // Remove old entries
    pipe.ZCard(fullKey) // Count current entries
    pipe.ZAdd(fullKey, &redis.Z{Score: float64(now), Member: now}) // Add current entry
    pipe.Expire(fullKey, 2*time.Minute) // Set expiration

    cmds, err := pipe.Exec()
    if err != nil {
        return false
    }

    count := cmds[1].(*redis.IntCmd).Val()
    return count <= 100 // Allow up to 100 requests per minute
}
```

### 3. Database Storage

```go
// Database-based rate limiter
type DatabaseRateLimiter struct {
    db *sql.DB
}

func NewDatabaseRateLimiter(db *sql.DB) *DatabaseRateLimiter {
    return &DatabaseRateLimiter{db: db}
}

func (l *DatabaseRateLimiter) Allow(key string) bool {
    now := time.Now()
    cutoff := now.Add(-1 * time.Minute)

    // Count requests in the last minute
    var count int
    err := l.db.QueryRow(`
        SELECT COUNT(*) FROM rate_limit_requests
        WHERE request_key = $1 AND created_at > $2
    `, key, cutoff).Scan(&count)

    if err != nil {
        return false
    }

    if count >= 100 {
        return false
    }

    // Record current request
    _, err = l.db.Exec(`
        INSERT INTO rate_limit_requests (request_key, created_at)
        VALUES ($1, $2)
    `, key, now)

    return err == nil
}
```

## Advanced Features

### 1. Dynamic Rate Limiting

```go
// Dynamic rate limiting based on user behavior
func DynamicRateLimiting(c *gin.Context) {
    userID := c.GetString("user_id")

    // Get user's rate limit based on their behavior
    userLimit := getUserRateLimit(userID)

    // Apply dynamic rate limiting
    limiter := NewSlidingWindowLimiter(1*time.Minute, userLimit)

    if !limiter.Allow(userID) {
        c.JSON(429, gin.H{"error": "Rate limit exceeded"})
        c.Abort()
        return
    }

    c.Next()
}

// Get user-specific rate limit
func getUserRateLimit(userID string) int {
    // Implement logic to determine user's rate limit
    // based on their subscription, behavior, etc.

    // Example: Premium users get higher limits
    if isPremiumUser(userID) {
        return 1000
    }

    // Example: Users with suspicious activity get lower limits
    if hasSuspiciousActivity(userID) {
        return 10
    }

    return 100 // Default limit
}
```

### 2. Rate Limit Headers

```go
// Add rate limit headers to response
func addRateLimitHeaders(c *gin.Context, limiter interfaces.RateLimiter, key string) {
    c.Header("X-RateLimit-Limit", strconv.Itoa(limiter.GetLimit()))
    c.Header("X-RateLimit-Remaining", strconv.Itoa(limiter.GetRemaining(key)))
    c.Header("X-RateLimit-Reset", strconv.FormatInt(limiter.GetResetTime(key), 10))
    c.Header("X-RateLimit-Reset-Time", time.Unix(limiter.GetResetTime(key), 0).Format(time.RFC1123))
}
```

### 3. Rate Limit Exemption

```go
// Rate limit exemption for certain users
func RateLimitExemptionMiddleware(exemptUsers []string) gin.HandlerFunc {
    return func(c *gin.Context) {
        userID := c.GetString("user_id")

        for _, exempt := range exemptUsers {
            if userID == exempt {
                c.Set("rate_limit_exempt", true)
                break
            }
        }

        c.Next()
    }
}

// Modified rate limiting middleware
func RateLimitMiddlewareWithExemption(limiter interfaces.RateLimiter, keyFunc func(c *gin.Context) string) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Check if user is exempt
        if exempt, exists := c.Get("rate_limit_exempt"); exists && exempt.(bool) {
            c.Next()
            return
        }

        key := keyFunc(c)

        if !limiter.Allow(key) {
            c.JSON(429, gin.H{"error": "Rate limit exceeded"})
            c.Abort()
            return
        }

        c.Next()
    }
}
```

## Monitoring and Analytics

### 1. Rate Limit Metrics

```go
// Rate limit metrics
type RateLimitMetrics struct {
    TotalRequests    int64
    BlockedRequests  int64
    AverageResponseTime time.Duration
}

// Collect metrics
func collectRateLimitMetrics(key string, allowed bool, responseTime time.Duration) {
    metrics := getMetrics(key)

    atomic.AddInt64(&metrics.TotalRequests, 1)
    if !allowed {
        atomic.AddInt64(&metrics.BlockedRequests, 1)
    }

    // Update average response time
    metrics.AverageResponseTime = (metrics.AverageResponseTime + responseTime) / 2
}
```

### 2. Alerting

```go
// Rate limit alerting
func checkRateLimitAlerts(key string, blockedCount int64) {
    if blockedCount > 1000 { // Alert threshold
        sendAlert(fmt.Sprintf("High rate limiting activity for key: %s", key))
    }
}

// Send alert
func sendAlert(message string) {
    // Implement your alerting mechanism
    // Email, Slack, PagerDuty, etc.
    log.Printf("ALERT: %s", message)
}
```

## Testing

### Unit Tests

```go
func TestRateLimiting(t *testing.T) {
    limiter := NewSlidingWindowLimiter(1*time.Minute, 5)

    // Test rate limiting
    for i := 0; i < 5; i++ {
        assert.True(t, limiter.Allow("test-key"))
    }

    // Should be blocked
    assert.False(t, limiter.Allow("test-key"))
}

func TestRateLimitingReset(t *testing.T) {
    limiter := NewSlidingWindowLimiter(100*time.Millisecond, 5)

    // Use up all tokens
    for i := 0; i < 5; i++ {
        limiter.Allow("test-key")
    }

    // Wait for window to reset
    time.Sleep(150 * time.Millisecond)

    // Should be allowed again
    assert.True(t, limiter.Allow("test-key"))
}
```

### Integration Tests

```go
func TestRateLimitingMiddleware(t *testing.T) {
    limiter := NewSlidingWindowLimiter(1*time.Minute, 3)

    r := gin.New()
    r.POST("/test", RateLimitMiddleware(limiter, IPKeyFunc), func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "success"})
    })

    // Test rate limiting
    for i := 0; i < 3; i++ {
        resp := performRequest(r, "POST", "/test", nil)
        assert.Equal(t, 200, resp.Code)
    }

    // Should be blocked
    resp := performRequest(r, "POST", "/test", nil)
    assert.Equal(t, 429, resp.Code)
}
```

## Best Practices

### 1. Configuration

- Set appropriate limits for different endpoints
- Use different strategies for different use cases
- Monitor and adjust limits based on usage patterns

### 2. User Experience

- Provide clear error messages when rate limited
- Include retry-after information
- Consider user-specific limits

### 3. Security

- Use IP-based limiting for anonymous endpoints
- Implement user-based limiting for authenticated endpoints
- Consider geographic-based limiting for global applications

### 4. Performance

- Use efficient storage backends (Redis recommended)
- Implement cleanup mechanisms for expired data
- Monitor memory usage for in-memory limiters

## Next Steps

- [Security Features](security.md) - Implement advanced security measures
- [Configuration](../configuration/auth.md) - Customize your rate limiting setup
- [API Reference](../api/endpoints.md) - Explore the complete API
- [Examples](../examples/basic-auth.md) - See complete implementation examples
