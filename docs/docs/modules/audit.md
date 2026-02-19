---
id: audit
title: Audit Module
sidebar_label: Audit
sidebar_position: 8
---

# Audit Module

Logs security-relevant events for compliance and debugging. Provides both self-service endpoints (users can view their own audit trail) and admin endpoints.

## Features

- Automatic event logging via hooks (auth, user, admin, security events)
- Configurable event categories
- Per-severity retention policies
- Sampling support for high-traffic events
- User self-service audit endpoints

## Registration

```go
import "github.com/bete7512/goauth/internal/modules/audit"

a.Use(audit.New(&audit.Config{
    TrackAuthEvents:     true,
    TrackUserEvents:     true,
    TrackAdminEvents:    true,
    TrackSecurityEvents: true,
    RetentionDays: map[string]int{
        "info":     30,
        "warning":  90,
        "critical": 365,
    },
    SampleRate: 1.0,  // 1.0 = log everything, 0.5 = 50%
}))
```

## Configuration

```go
type Config struct {
    AuditLogRepository  models.AuditLogRepository  // Custom repo (optional)
    RetentionDays       map[string]int              // Per-severity retention
    TrackAuthEvents     bool                        // Login, logout, signup
    TrackUserEvents     bool                        // Profile, password changes
    TrackAdminEvents    bool                        // Admin CRUD operations
    TrackSecurityEvents bool                        // 2FA, suspicious activity
    SampleRate          float64                     // 0.0–1.0 sampling rate
}
```

## Endpoints

### User Self-Service

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/me/audit` | ✓ | Get your audit logs |
| GET | `/me/audit/logins` | ✓ | Get your login history |
| GET | `/me/audit/changes` | ✓ | Get your profile changes |
| GET | `/me/audit/security` | ✓ | Get your security events |

### Admin

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/admin/audit` | Admin | List all audit logs |
| GET | `/admin/audit/users/{id}` | Admin | Get audit logs for a user |
| GET | `/admin/audit/actions/{action}` | Admin | Get logs by action type |

## Tracked Events

When enabled, the module automatically subscribes to:

- **Auth**: `EventAfterSignup`, `EventAfterLogin`, `EventAfterLogout`, `EventAuthLoginFailed`
- **User**: `EventAfterProfileUpdate`, `EventAfterPasswordChange`, `EventAfterEmailVerification`
- **Admin**: `EventAdminAction`, `EventAdminUserUpdate`, `EventAdminUserDelete`
- **Security**: `EventAfter2FASetup`, `EventAfter2FADisable`
