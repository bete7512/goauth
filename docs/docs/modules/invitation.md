---
id: invitation
title: Invitation
sidebar_label: Invitation
sidebar_position: 13
---

# Invitation Module

The Invitation module provides standalone, platform-level invitations. Use it to invite users to your platform, beta program, referral system, or any non-organization context. For organization-scoped invitations, see the [Organization module](organization.md).

## Capabilities

- **Invite by Email** -- Send invitations to any email address with a configurable purpose (e.g., `"platform"`, `"beta"`, `"referral"`).
- **Invite-Only Registration** -- The accept endpoint creates a new user account if the email doesn't exist yet. This enables invite-only platforms where signup is gated by invitation.
- **Public Accept/Decline** -- Accept and decline endpoints are public (no auth required). The invitation token is the authorization. New users provide name + password; existing users just accept.
- **Auth Tokens on Accept** -- The accept endpoint returns JWT access and refresh tokens, so the user is immediately logged in after accepting.
- **Inviter-Scoped** -- Only the inviter can list and cancel their own invitations.
- **Purpose Field** -- Tag invitations with a purpose string for filtering and business logic.
- **Metadata** -- Attach arbitrary JSON metadata to invitations for consumer-defined data.
- **Email Notifications** -- When the notification module is registered, invitation emails are sent automatically (no config flag needed).

## Registration

```go
import "github.com/bete7512/goauth/pkg/modules/invitation"

a.Use(invitation.New(&invitation.Config{
    CallbackURL:    "https://app.example.com/invite", // frontend page
    DefaultPurpose: "platform",
    InvitationExpiry: 7 * 24 * time.Hour,
}))

// Or with defaults (7-day expiry, "platform" purpose)
a.Use(invitation.New(nil))
```

## Configuration

```go
type Config struct {
    // InvitationExpiry is how long an invitation remains valid. Default: 7 days.
    InvitationExpiry time.Duration

    // CallbackURL is the frontend URL for invitation acceptance.
    // The token is appended as ?token=<token>.
    // If empty, invitation emails are sent without a clickable link.
    CallbackURL string

    // DefaultPurpose is used when no purpose is specified. Default: "platform".
    DefaultPurpose string

    // AllowedPurposes restricts which purpose values can be used.
    // If empty, any purpose string is allowed.
    AllowedPurposes []string

    // MaxPendingPerEmail limits pending invitations per email. -1 = unlimited (default).
    MaxPendingPerEmail int
}
```

## Endpoints

### Authenticated routes

| Method | Path | Route Name | Description |
|--------|------|------------|-------------|
| POST | `/invitations` | `invitation.send` | Send an invitation (requires auth + admin) |
| GET | `/invitations` | `invitation.list` | List invitations sent by the current user |
| GET | `/invitations/my` | `invitation.my` | List pending invitations for current user's email |
| DELETE | `/invitations/{invId}` | `invitation.cancel` | Cancel a pending invitation (inviter only) |

### Public routes (no auth required)

| Method | Path | Route Name | Description |
|--------|------|------------|-------------|
| POST | `/invitations/accept` | `invitation.accept` | Accept an invitation by token |
| POST | `/invitations/decline` | `invitation.decline` | Decline an invitation by token |

### Accept invitation flow

**Request:**
```json
{
    "token": "invitation-token-from-email",
    "name": "John Doe",
    "password": "securepassword123"
}
```

- `token` is always required
- `name` and `password` are required only when the invited email has no existing account

**Response:**
```json
{
    "data": {
        "access_token": "eyJ...",
        "refresh_token": "eyJ...",
        "user": {
            "id": "uuid",
            "email": "john@example.com",
            "name": "John Doe",
            "email_verified": true
        },
        "is_new_user": true
    }
}
```

## Invitation Flow

```
1. Inviter calls POST /invitations {"email": "john@example.com"}
2. System creates invitation record, emits EventInvitationSent
3. Notification module sends email with link to frontend: https://app.example.com/invite?token=xxx
4. Recipient clicks link -> frontend page
5a. New user: frontend shows name+password form, calls POST /invitations/accept with token+name+password
5b. Existing user: frontend calls POST /invitations/accept with just the token
6. System creates user (if new), marks invitation accepted, returns auth tokens
7. User is immediately logged in
```

## Model

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | UUID primary key |
| `Email` | `string` | Invitee email address |
| `Purpose` | `string` | Invitation purpose (e.g., `"platform"`, `"beta"`) |
| `InviterID` | `string` | UUID of the user who sent the invitation |
| `Token` | `string` | Unique invitation token (hidden from API responses) |
| `Status` | `string` | `pending`, `accepted`, `declined`, or `expired` |
| `Metadata` | `string` | Optional JSON metadata |
| `ExpiresAt` | `time.Time` | When the invitation expires |
| `CreatedAt` | `time.Time` | Creation timestamp |
| `AcceptedAt` | `*time.Time` | When the invitation was accepted |

Table: `invitations`

## Events

| Event | Fired When |
|-------|------------|
| `invitation.sent` | An invitation is sent |
| `invitation.accepted` | An invitation is accepted |
| `invitation.declined` | An invitation is declined |

## Email Notifications

When the notification module is registered with an `EmailSender`, invitation emails are sent automatically on `EventInvitationSent`. No config flag needed -- the hook is always active.

The email uses the `"invitation"` template with these variables:
- `{{.InviterName}}` -- name of the person who sent the invitation
- `{{.Purpose}}` -- invitation purpose
- `{{.InviteLink}}` -- frontend link (only when `CallbackURL` is configured)
- `{{.ExpiresAt}}` -- formatted expiry date
- `{{.Brand.*}}` -- branding variables (AppName, PrimaryColor, etc.)

Override the template:
```go
notification.New(&notification.Config{
    EmailTemplates: map[string]notification.EmailTemplate{
        "invitation": {
            Name:    "invitation",
            Subject: "Join us on {{.Brand.AppName}}!",
            TextBody: "{{.InviterName}} invited you. Accept: {{.InviteLink}}",
            HTMLBody: "<h1>You're invited!</h1><a href='{{.InviteLink}}'>Accept</a>",
        },
    },
})
```

## Dependencies

- **Core module** (auto-registered)
- **Notification module** (optional, for email delivery)
