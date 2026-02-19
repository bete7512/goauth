---
id: admin
title: Admin Module
sidebar_label: Admin
sidebar_position: 7
---

# Admin Module

Admin-only endpoints for user management. All routes require both authentication and admin authorization middleware.

## Registration

```go
import "github.com/bete7512/goauth/internal/modules/admin"

a.Use(admin.New(nil))
```

Or with custom repositories:

```go
a.Use(admin.New(&admin.Config{
    UserRepository:     customUserRepo,
    AuditLogRepository: customAuditRepo,
}))
```

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/admin/users` | Admin | List all users |
| GET | `/admin/users/{id}` | Admin | Get user by ID |
| PUT | `/admin/users/{id}` | Admin | Update user |
| DELETE | `/admin/users/{id}` | Admin | Delete user |

All endpoints require `Authorization: Bearer <token>` from a user with admin privileges.

## Events

Subscribes to `EventAdminAction` for admin action logging.
