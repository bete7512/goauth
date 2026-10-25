---
id: admin
title: Admin Module
sidebar_label: Admin
sidebar_position: 7
---

# Admin Module

> **Experimental.** This module works and is tested, but its API and schema may change during the beta.

The Admin module provides a complete administrative interface for managing users in your application. All routes are protected by both authentication and admin authorization middleware, ensuring only privileged users (those with `is_super_admin: true`) can access them. It supports listing users with pagination, sorting, and filtering, as well as viewing, updating, and deleting individual users.

## Capabilities

- **User Listing** — Paginated, sortable list of all users. Supports sorting by `created_at`, `email`, `username`, and `name`. Uses `offset`/`limit` pagination.
- **User Details** — Fetch full user profile by ID, including verification status, login history, and account state.
- **User Updates** — Modify user fields (name, email, active status, admin flag, etc.) from the admin panel.
- **User Deletion** — Permanently delete user accounts. Hard delete (no soft deletes).
- **Admin-Only Middleware** — The `MiddlewareAdminAuth` middleware (priority 40) is applied exclusively to admin routes. It verifies the authenticated user has admin privileges.
- **Audit Event Integration** — Subscribes to `EventAdminAction` for admin action logging. Updates and deletes emit events consumed by Audit. Read operations do not automatically produce an audit event.
- **Custom Storage** — Pass custom `UserRepository` and `AuditLogRepository` implementations to use your own data layer.

## Registration

```go
import "github.com/bete7512/goauth/pkg/modules/admin"

if err := a.Use(admin.New(nil)); err != nil {
    return err
}
```

Or with custom repositories:

```go
if err := a.Use(admin.New(&admin.Config{
    UserRepository:     customUserRepo,
    AuditLogRepository: customAuditRepo,
})); err != nil {
    return err
}
```

## Configuration

```go
type Config struct {
    AuditLogRepository models.AuditLogRepository // Custom audit log repo (optional)
    UserRepository     models.UserRepository     // Custom user repo (optional)
}
```

Both fields are optional. When nil, repositories are obtained from the shared storage layer during initialization.

## Dependencies

- **Core** -- uses `deps.Storage.Core().Users()` for the user repository.

## Endpoints

| Method | Path | Middleware | Description |
|--------|------|------------|-------------|
| GET | `/admin/users` | Auth + Admin | List all users |
| GET | `/admin/users/{id}` | Auth + Admin | Get user by ID |
| PUT | `/admin/users/{id}` | Auth + Admin | Update user |
| DELETE | `/admin/users/{id}` | Auth + Admin | Delete user |

All endpoints require a verified access credential from a user with `is_super_admin: true`. Credential transport follows `AuthMode` (bearer, cookie, or both).

## Middleware

The module registers the `MiddlewareAdminAuth` middleware (priority 40). It is not global -- it is applied only to admin routes.

## Extensibility

### Custom Storage

Both `UserRepository` and `AuditLogRepository` can be replaced with custom implementations:

```go
if err := a.Use(admin.New(&admin.Config{
    UserRepository:     myCustomUserRepo,     // implements models.UserRepository
    AuditLogRepository: myCustomAuditRepo,    // implements models.AuditLogRepository
})); err != nil {
    return err
}
```

When `nil`, repositories are obtained from the shared storage layer during initialization (`deps.Storage.Core().Users()` for users).

## Events

Subscribes to `EventAdminAction` for admin action logging. The update and delete services emit `EventAdminUserUpdated` and `EventAdminUserDeleted`; the Audit module records these when admin-event tracking is enabled. This does not cover every administrative read.
