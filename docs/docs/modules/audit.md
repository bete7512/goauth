---
id: audit
title: Audit Module
sidebar_label: Audit
sidebar_position: 8
---

# Audit Module

The Audit module provides comprehensive security event logging for compliance, debugging, and user transparency. It automatically subscribes to lifecycle events across all modules and writes structured audit log entries with action names, severity levels, actor IDs, IP addresses, and metadata. It serves two audiences: end users who want to see their own activity history, and administrators who need a full audit trail for compliance and incident investigation.

## Capabilities

- **Automatic Event Logging** — Subscribes to auth, user, admin, and security events via hooks. No manual logging calls needed — register the module and it starts recording.
- **Four Event Categories** — Auth events (login, logout, password changes, 2FA), user events (profile updates, email/phone changes), admin events (user CRUD, role assignments), and security events (suspicious logins, account lockouts, token invalidations). Each category can be independently toggled on or off.
- **Per-Action Retention Policies** — Configure how long each category of logs is retained. Use wildcard patterns like `"auth.*": 90` (days) or `"security.*": -1` (forever). Different compliance requirements can be met per event type.
- **Automatic Background Cleanup** — A background goroutine runs every 24 hours to purge expired audit logs according to retention policies. Respects `ctx.Done()` for graceful shutdown.
- **Manual Cleanup Trigger** — Admin endpoint to trigger immediate log cleanup on demand.
- **Sampling Support** — For high-traffic events, set `SampleRate` (0.0 to 1.0) to log only a percentage of events. Useful for reducing storage costs on non-critical event categories.
- **User Self-Service Endpoints** — Users can view their own audit trail, login history, profile changes, and security events. Builds user trust and supports self-service security review.
- **Admin Audit Endpoints** — Admins can query the full audit trail, filter by user ID or action type, and trigger manual cleanup.
- **Severity Levels** — Each event is logged with a severity (`info`, `warning`, `critical`) for easy filtering and alerting.
- **Custom Audit Storage** — Pass a custom `AuditLogRepository` to store audit logs in a separate database, append-only store, or external SIEM system.

## Registration

```go
import "github.com/bete7512/goauth/pkg/modules/audit"

// Default config: all event types tracked, 90/365/forever retention
a.Use(audit.New(nil))
```

Or with custom settings:

```go
a.Use(audit.New(&audit.Config{
    TrackAuthEvents:     true,
    TrackUserEvents:     true,
    TrackAdminEvents:    true,
    TrackSecurityEvents: true,
    RetentionDays: map[string]int{
        "auth.*":     90,   // Keep auth logs 90 days
        "user.*":     90,   // Keep user logs 90 days
        "admin.*":    365,  // Keep admin logs 1 year
        "security.*": -1,   // Keep security logs forever
    },
    SampleRate: 1.0, // 1.0 = log everything, 0.5 = 50%
}))
```

## Configuration

```go
type Config struct {
    AuditLogRepository  models.AuditLogRepository // Custom repo (optional)
    RetentionDays       map[string]int             // Per-action-pattern retention (days, -1 = forever)
    TrackAuthEvents     bool                       // Login, logout, password, 2FA
    TrackUserEvents     bool                       // Profile, email, phone, avatar
    TrackAdminEvents    bool                       // Admin CRUD operations
    TrackSecurityEvents bool                       // Suspicious login, lockout, revocation
    SampleRate          float64                    // 0.0-1.0 sampling rate
}
```

### Default retention keys

When `cfg` is nil, `New(nil)` uses these defaults:

| Key | Days | Meaning |
|-----|------|---------|
| `auth.*` | 90 | Auth events kept 90 days |
| `user.*` | 90 | User events kept 90 days |
| `admin.*` | 365 | Admin events kept 1 year |
| `security.*` | -1 | Security events kept forever |

## Dependencies

- **Core** -- depends on core for authentication middleware.

## Endpoints

### User Self-Service

| Method | Path | Middleware | Description |
|--------|------|------------|-------------|
| GET | `/me/audit` | Auth | Get your audit logs |
| GET | `/me/audit/logins` | Auth | Get your login history |
| GET | `/me/audit/changes` | Auth | Get your profile changes |
| GET | `/me/audit/security` | Auth | Get your security events |

### Admin

| Method | Path | Middleware | Description |
|--------|------|------------|-------------|
| GET | `/admin/audit` | Auth + Admin | List all audit logs |
| GET | `/admin/audit/users/{id}` | Auth + Admin | Get audit logs for a user |
| GET | `/admin/audit/actions/{action}` | Auth + Admin | Get logs by action type |
| POST | `/admin/audit/cleanup` | Auth + Admin | Trigger manual log cleanup |

## Tracked Events

The module subscribes to events via `RegisterHooks`. Each category is independently togglable.

### Auth Events (`TrackAuthEvents`)

| Event | Audit Action | Severity |
|-------|-------------|----------|
| `EventAuthLoginSuccess` | `auth.login.success` | info |
| `EventAuthLoginFailed` | `auth.login.failed` | warning |
| `EventAuthLogout` | `auth.logout` | info |
| `EventAuthPasswordChanged` | `auth.password.changed` | info |
| `EventAuth2FAEnabled` | `auth.2fa.enabled` | info |
| `EventAuth2FADisabled` | `auth.2fa.disabled` | warning |

### User Events (`TrackUserEvents`)

| Event | Audit Action | Severity |
|-------|-------------|----------|
| `EventUserProfileUpdated` | `user.profile.updated` | info |
| `EventUserEmailChanged` | `user.email.changed` | info |
| `EventUserEmailVerified` | `user.email.verified` | info |
| `EventUserPhoneChanged` | `user.phone.changed` | info |
| `EventUserAvatarUpdated` | `user.avatar.updated` | info |

### Admin Events (`TrackAdminEvents`)

| Event | Audit Action | Severity |
|-------|-------------|----------|
| `EventAdminUserCreated` | `admin.user.created` | info |
| `EventAdminUserUpdated` | `admin.user.updated` | info |
| `EventAdminUserDeleted` | `admin.user.deleted` | warning |
| `EventAdminUserSuspended` | `admin.user.suspended` | warning |
| `EventAdminRoleAssigned` | `admin.role.assigned` | info |
| `EventAdminRoleRevoked` | `admin.role.revoked` | warning |

### Security Events (`TrackSecurityEvents`)

| Event | Audit Action | Severity |
|-------|-------------|----------|
| `EventSecuritySuspiciousLogin` | `security.suspicious.login` | critical |
| `EventSecurityAccountLocked` | `security.account.locked` | warning |
| `EventSecuritySessionRevoked` | `security.session.revoked` | info |
| `EventSecurityTokenInvalidated` | `security.token.invalidated` | info |

## Extensibility

### Custom Audit Storage

Pass a custom `AuditLogRepository` to store audit logs in a separate database, external SIEM, or append-only store:

```go
a.Use(audit.New(&audit.Config{
    AuditLogRepository: myCustomAuditRepo, // implements models.AuditLogRepository
    TrackAuthEvents:    true,
    TrackSecurityEvents: true,
}))
```

When `nil`, the repository is obtained from the shared storage layer during initialization.

### Sorting and Pagination

Admin audit endpoints support sorting by `created_at`, `action`, `severity`, and `actor_id`. Pagination uses `offset`/`limit` parameters. User self-service endpoints are automatically scoped to the authenticated user's ID.

## Next Steps

- [Admin Module](admin.md) — User management with audit integration
- [Core Module](core.md) — Core auth features
- [API Reference](/docs/api/endpoints) — All endpoints
