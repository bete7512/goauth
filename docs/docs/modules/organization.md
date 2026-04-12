---
id: organization
title: Organization
sidebar_label: Organization
sidebar_position: 12
---

# Organization Module

The Organization module adds multi-tenant organization support to your application. It provides a complete workspace/team management system with role-based access control, invitation workflows, and organization-scoped middleware. Users can create organizations, invite members, assign roles, and switch between organizations. JWT claims are automatically enriched with organization context on login.

## Capabilities

- **Multi-Organization Membership** — Users can belong to multiple organizations simultaneously. Each membership has an independent role.
- **Role Hierarchy** — Three built-in roles: `owner` (full control, can delete org), `admin` (manage members and invitations), `member` (read access). Role assignments are enforced at the middleware level.
- **Invitation Flow** — Invite users by email with a role assignment. Invitations have configurable expiry (default: 7 days), support accept/decline actions, and can be cancelled by org admins. Optional frontend callback URL for invitation acceptance.
- **Organization Switching** — Users switch their active organization via `POST /org/switch`. The active org is embedded in JWT claims, so downstream services can scope queries without additional lookups.
- **Org-Scoped JWT Claims** — The auth interceptor (priority 50) enriches JWT tokens on login with `active_org_id`, `org_role`, and `org_memberships` (array of all memberships with `org_id` and `role`).
- **Auto-Create on Signup** — When `AutoCreateOrg: true`, a default organization is automatically created for every new user. The org name supports placeholders: `{name}`, `{email}`, `{username}`.
- **Organization Context Middleware** — The `org.auth` middleware (priority 45) extracts `{orgId}` from the URL, verifies the user is a member, and injects the org context for handlers.
- **Member Management** — List, view, update roles, and remove members. Owners and admins can manage the membership roster.
- **Organization CRUD** — Create, read, update, and delete organizations. Includes slug generation for URL-safe identifiers and optional metadata (JSON) and logo URL fields.
- **Configurable Member Limits** — Set `MaxMembersPerOrg` to enforce organization size limits. Use `-1` for unlimited (default).

## Registration

```go
import (
    "time"

    "github.com/bete7512/goauth/pkg/modules/organization"
)

a.Use(organization.New(&organization.Config{
    AutoCreateOrg:         true,
    DefaultOrgNamePattern: "{name}'s workspace",
    MaxMembersPerOrg:      50,
    InvitationExpiry:      7 * 24 * time.Hour,
    InvitationCallbackURL: "http://localhost:3000/invite",
}))

// Or with defaults (no auto-create, unlimited members, 7-day invitations)
a.Use(organization.New(nil))
```

## Configuration

```go
// organization.Config is a type alias for the internal config.
type Config struct {
    // Create a default org when a user signs up (default: false)
    AutoCreateOrg bool

    // Pattern for auto-created org names.
    // Supports {name}, {email}, {username} placeholders.
    // Default: "{name}'s workspace"
    DefaultOrgNamePattern string

    // Maximum members per organization. -1 = unlimited (default).
    MaxMembersPerOrg int

    // How long invitation tokens remain valid (default: 7 days)
    InvitationExpiry time.Duration

    // Frontend URL for invitation acceptance.
    // Token appended as query param: {URL}?token=xxx
    // If empty, the accept endpoint returns JSON response.
    InvitationCallbackURL string
}
```

## Endpoints

### User-level routes (no org context)

These routes require authentication (`core.auth` middleware) but do not require an organization context.

| Method | Path                         | Route Name                 | Description                      |
|--------|------------------------------|----------------------------|----------------------------------|
| POST   | `/org`                       | `org.create`               | Create a new organization        |
| GET    | `/org/my`                    | `org.my`                   | List organizations for current user |
| POST   | `/org/switch`                | `org.switch`               | Switch active organization       |
| GET    | `/org/my/invitations`        | `org.my.invitations`       | List pending invitations for current user |

### Public routes (no auth required)

The accept and decline endpoints are public. The invitation token is the authorization. New users provide name + password to create an account during acceptance.

| Method | Path                         | Route Name                 | Description                      |
|--------|------------------------------|----------------------------|----------------------------------|
| POST   | `/org/invitations/accept`    | `org.invitations.accept`   | Accept an invitation (creates user if needed) |
| POST   | `/org/invitations/decline`   | `org.invitations.decline`  | Decline an invitation            |

### Organization-scoped routes

These routes require both authentication and the `org.auth` middleware, which validates organization membership and injects the org context.

| Method | Path                                  | Route Name                 | Description                      |
|--------|---------------------------------------|----------------------------|----------------------------------|
| GET    | `/org/{orgId}`                        | `org.get`                  | Get organization details         |
| PUT    | `/org/{orgId}`                        | `org.update`               | Update organization              |
| DELETE | `/org/{orgId}`                        | `org.delete`               | Delete organization              |
| GET    | `/org/{orgId}/members`                | `org.members.list`         | List organization members        |
| GET    | `/org/{orgId}/members/{userId}`       | `org.members.get`          | Get a specific member            |
| PUT    | `/org/{orgId}/members/{userId}`       | `org.members.update`       | Update member role               |
| DELETE | `/org/{orgId}/members/{userId}`       | `org.members.remove`       | Remove a member                  |
| POST   | `/org/{orgId}/invite`                 | `org.invite`               | Send an invitation               |
| GET    | `/org/{orgId}/invitations`            | `org.invitations.list`     | List invitations for the org     |
| DELETE | `/org/{orgId}/invitations/{invId}`    | `org.invitations.cancel`   | Cancel a pending invitation      |

## Roles

| Role     | Description                                                |
|----------|------------------------------------------------------------|
| `owner`  | Full control. Created automatically when a user creates an org. Can delete the org and manage all members. |
| `admin`  | Can manage members and invitations. Cannot delete the org. |
| `member` | Basic access. Can view org details and member list.        |

## Models

### Organization

| Field      | Type       | Description                              |
|------------|------------|------------------------------------------|
| `ID`       | `string`   | UUID primary key                         |
| `Name`     | `string`   | Organization name                        |
| `Slug`     | `string`   | URL-safe unique identifier               |
| `OwnerID`  | `string`   | UUID of the user who owns the org        |
| `LogoURL`  | `string`   | Optional logo URL                        |
| `Metadata` | `string`   | Optional JSON metadata                   |
| `Active`   | `bool`     | Whether the org is active (default: true)|
| `CreatedAt`| `time.Time`| Creation timestamp                       |
| `UpdatedAt`| `*time.Time`| Last update timestamp                   |

### OrganizationMember

| Field      | Type       | Description                              |
|------------|------------|------------------------------------------|
| `ID`       | `string`   | UUID primary key                         |
| `OrgID`    | `string`   | Organization UUID                        |
| `UserID`   | `string`   | User UUID                                |
| `Role`     | `string`   | `owner`, `admin`, or `member`            |
| `JoinedAt` | `time.Time`| When the user joined                     |
| `UpdatedAt`| `*time.Time`| Last update timestamp                   |

### OrgInvitation

Table: `org_invitations`

| Field       | Type        | Description                              |
|-------------|-------------|------------------------------------------|
| `ID`        | `string`    | UUID primary key                         |
| `OrgID`     | `string`    | Organization UUID                        |
| `Email`     | `string`    | Invitee email address                    |
| `Role`      | `string`    | Role assigned on acceptance              |
| `InviterID` | `string`    | UUID of the user who sent the invitation |
| `Token`     | `string`    | Unique invitation token (not exposed in JSON) |
| `Status`    | `string`    | `pending`, `accepted`, `declined`, or `expired` |
| `ExpiresAt` | `time.Time` | When the invitation expires              |
| `CreatedAt` | `time.Time` | Creation timestamp                       |
| `AcceptedAt`| `*time.Time`| When the invitation was accepted         |

## Middleware

The module registers an `org.auth` middleware (priority 45, below auth at 50). This middleware is not global -- it is applied per-route via the route's `Middlewares` field on all organization-scoped routes.

The middleware:
1. Extracts `{orgId}` from the URL path
2. Verifies the authenticated user is a member of that organization
3. Injects the organization context for handlers to use

## Auth Interceptor

The organization module registers an auth interceptor (priority 50) that enriches JWT claims on login with:

- `active_org_id` -- the user's first organization ID
- `org_role` -- the user's role in that organization
- `org_memberships` -- array of all org memberships with `org_id` and `role`

## Events

| Event                      | Fired When                          |
|----------------------------|-------------------------------------|
| `org.created`              | Organization is created             |
| `org.updated`              | Organization is updated             |
| `org.deleted`              | Organization is deleted             |
| `org.member.added`         | A member is added to an org         |
| `org.member.removed`       | A member is removed from an org     |
| `org.member.role.changed`  | A member's role is changed          |
| `org.invitation.sent`      | An invitation is sent               |
| `org.invitation.accepted`  | An invitation is accepted           |
| `org.invitation.declined`  | An invitation is declined           |
| `org.switched`             | A user switches active organization |

## Hooks

When `AutoCreateOrg` is `true`, the module subscribes to `EventAfterSignup` and automatically creates an organization for the new user using the `DefaultOrgNamePattern`.

## Extensibility

### Custom Storage

The Organization module accepts custom storage through the module constructor. When using the default, repositories are obtained from the shared storage layer during initialization.

### Event Hooks

Subscribe to organization events for custom logic (e.g., provisioning resources when an org is created, notifying members when roles change):

```go
a.On(types.EventOrgCreated, func(ctx context.Context, e *types.Event) error {
    // Provision workspace resources, create default channels, etc.
    return nil
})

a.On(types.EventOrgMemberAdded, func(ctx context.Context, e *types.Event) error {
    // Send welcome message, grant access to shared resources, etc.
    return nil
})
```

## Dependencies

- **Core module** (auto-registered)
