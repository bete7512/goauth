---
id: ratelimit
title: Rate Limit Module
sidebar_label: Rate Limit
sidebar_position: 14
---

# Rate Limit Module

The Rate Limit module puts request budgets on the built-in authentication routes so that one address cannot hammer the login endpoint and one targeted account cannot be guessed at from many addresses. It is **registered for you** during `Initialize()` with a sensible default rule set, the same way the Stateless module becomes the default authentication module. You only touch it to tune the limits, plug in a shared store, or turn it off.

## Capabilities

- **On by default** — No code needed. `auth.New` plus `Initialize` gives you the default rules with an in-memory store.
- **Two kinds of keys** — Rules count per client IP (`types.RateLimitKeyIP`), per submitted identifier such as the email, username or phone number in the request body (`types.RateLimitKeyIdentifier`), or per pair (`types.RateLimitKeyIPIdentifier`). Identifiers are stored only as digests.
- **Route patterns** — Rules target route names (`types.RouteLogin`, `"core.*"`) with optional exclusions, like every other GoAuth middleware.
- **Proxy aware** — `X-Forwarded-For` and `X-Real-IP` are honored only when the direct peer is listed in `Config.TrustedProxies`, so clients cannot forge their address. IPv6 clients share a `/64` bucket.
- **Standard responses** — `429 Too Many Requests` with `Retry-After`, plus `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` headers on every limited route.
- **Pluggable store** — The default store is per process. Implement `types.RateLimitStore` (for example with Redis) to enforce budgets across replicas.
- **Observable** — Each rejection emits `types.EventRateLimitExceeded`; the Audit module records it as `security.ratelimit.exceeded`.
- **Zero storage** — No database tables or migrations.

## Default rules

| Routes | Key | Budget |
|---|---|---|
| Login, two-factor verification, passkey login finish, magic-link verification, password reset, email and phone verification, invitation acceptance | IP | 30 per minute |
| The same routes | Identifier | 10 per 10 minutes |
| Forgot password, verification sends and resends, magic-link send and resend, two-factor resend, invitation send | IP | 10 per hour |
| The same routes | Identifier | 3 per hour |
| Signup | IP | 10 per hour |
| Availability check | IP | 30 per minute |
| Token refresh | IP | 120 per minute |
| OAuth login and callback, passkey registration and login begin | IP | 60 per minute |

Authenticated routes such as the profile endpoints carry no default rule. Budgets are token buckets: the full budget is available immediately and refills continuously at the stated rate.

## Configuration

### Tune the defaults

Pass `RateLimit` on the root configuration. `ExtraRules` are appended to the defaults; `Rules` replaces them.

```go
import (
    "time"

    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/types"
)

cfg := &config.Config{
    // ... storage, security, core ...
    TrustedProxies: []string{"10.0.0.0/8"}, // your load balancers
    RateLimit: &config.RateLimitModuleConfig{
        Allowlist: []string{"192.0.2.10"}, // health checker, never limited
        ExtraRules: []config.RateLimitRuleConfig{{
            Name:    "profile_ip",
            ApplyTo: []types.RouteName{types.RouteMe, types.RouteUpdateProfile},
            Key:     types.RateLimitKeyIP,
            Limit:   120,
            Window:  time.Minute,
        }},
    },
}
```

### Replace the rules

```go
import (
    "time"

    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/modules/ratelimit"
    "github.com/bete7512/goauth/pkg/types"
)

rules := ratelimit.DefaultRules()
rules = append(rules, config.RateLimitRuleConfig{
    Name:    "login_pair",
    ApplyTo: []types.RouteName{types.RouteLogin},
    Key:     types.RateLimitKeyIPIdentifier,
    Limit:   5,
    Window:  15 * time.Minute,
})
if err := a.Use(ratelimit.New(&config.RateLimitModuleConfig{Rules: rules})); err != nil {
    return err
}
```

Registering the module yourself with `a.Use` replaces the default registration.

### Use a shared store

```go
import (
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/modules/ratelimit"
)

if err := a.Use(ratelimit.New(&config.RateLimitModuleConfig{
    Store:      myRedisStore, // implements types.RateLimitStore
    FailClosed: false,        // allow requests if the store is unreachable (default)
})); err != nil {
    return err
}
```

A store implements three methods. `Take` must be atomic per key: two concurrent calls for the same key must observe one consistent budget. With Redis that is a single Lua script that reads the stored arrival time, applies the token-bucket arithmetic and writes the new value.

```go
type RateLimitStore interface {
    Take(ctx context.Context, key string, rule types.RateLimitRule, now time.Time) (types.RateLimitDecision, error)
    Reset(ctx context.Context, key string) error
    Close() error
}
```

### Turn it off

```go
cfg := &config.Config{
    // ...
    RateLimit: &config.RateLimitModuleConfig{Disabled: true},
}
```

### All options

| Field | Default | Meaning |
|---|---|---|
| `Disabled` | `false` | Turn rate limiting off entirely. |
| `Store` | in-memory | Counter storage; provide a shared implementation for several replicas. |
| `Rules` | `DefaultRules()` | Replaces the default rule set when non-nil. |
| `ExtraRules` | none | Appended to the active rule set. |
| `Allowlist` | none | IPs or CIDR blocks that are never limited. |
| `FailClosed` | `false` | Reject with `503` when the store fails instead of allowing. |
| `IPv6PrefixBits` | `64` | Prefix length that groups IPv6 clients. |
| `DisableHeaders` | `false` | Omit the `RateLimit-*` headers (`Retry-After` is always sent on `429`). |
| `MaxTrackedKeys` | `100000` | Cap on keys held by the in-memory store. |

`Config.TrustedProxies` lives on the root configuration because it describes the deployment, not the limiter; the Captcha module uses it too.

## Responses

A limited request receives:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 7
RateLimit-Limit: 10
RateLimit-Remaining: 0
RateLimit-Reset: 60
Content-Type: application/json

{"data":{"code":"RATE_LIMIT_EXCEEDED","message":"Too many requests. Please retry later."}}
```

Allowed requests on limited routes carry the same `RateLimit-*` headers for the tightest matching rule.

## Events

| Event | When | Data |
|---|---|---|
| `types.EventRateLimitExceeded` | A request is rejected | `*types.RateLimitExceededData` with route, rule name, key kind, a digest of the key, the client IP and the retry delay. The raw identifier is never included. |

## Notes

- The in-memory store is per process. Each replica enforces the budgets independently, which still bounds abuse per instance; use a shared store for exact global limits.
- Rate limiting is defense in depth. Account lockout still applies to failed passwords, and single-use codes keep their own attempt budgets.
- When the store fails the default is to allow the request and log a warning once per minute. Set `FailClosed` when exposure matters more than availability.
- Limits apply to GoAuth's own routes. Protect application routes behind `RequireAuth` with your framework's limiter or an extra rule on a custom route name.
