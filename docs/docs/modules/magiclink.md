---
id: magiclink
title: Magic Link Module
sidebar_label: Magic Link
sidebar_position: 11
---

# Magic Link Module

The Magic Link module provides passwordless authentication via email. Instead of passwords, users receive a one-time link (or code) that authenticates them directly. This eliminates password fatigue, reduces support tickets for forgotten passwords, and provides a streamlined login experience. It works seamlessly with the Notification module for email delivery.

## Capabilities

- **Passwordless Login** — Users authenticate by clicking a link sent to their email. No password to remember, no password to leak.
- **Code-Based Verification** — For mobile apps or scenarios where clicking a link is inconvenient, the same magic link email contains a short code that can be entered via `POST /magic-link/verify-code`.
- **Auto-Registration** — When `AutoRegister: true`, new email addresses that do not have an existing account are automatically registered. This combines signup and login into a single flow.
- **Configurable Token Expiry** — Magic link tokens expire after a configurable duration (default: 15 minutes).
- **Frontend Redirect or JSON Response** — If `CallbackURL` is set, the verify endpoint redirects to your frontend with tokens in the URL fragment (`#access_token=xxx&refresh_token=xxx`). If empty, returns a JSON `AuthResponse`.
- **Resend Support** — Users can request a new magic link via `/magic-link/resend` if the original email was not received.
- **Custom Storage** — Pass a custom `types.CoreStorage` to control where magic link tokens are stored.

## Registration

```go
import (
    "time"

    "github.com/bete7512/goauth/pkg/modules/magiclink"
    "github.com/bete7512/goauth/pkg/config"
)

a.Use(magiclink.New(&config.MagicLinkModuleConfig{
    TokenExpiry:  15 * time.Minute,
    AutoRegister: true,
    CallbackURL:  "http://localhost:3000/auth/magic",
}, nil))
```

The second argument is an optional `types.CoreStorage`. Pass `nil` to use the default storage from `deps.Storage.Core()`.

## Configuration

```go
type MagicLinkModuleConfig struct {
    // How long magic link tokens remain valid (default: 15 minutes)
    TokenExpiry time.Duration

    // Create a new user if the email doesn't exist (default: false)
    AutoRegister bool

    // Frontend URL to redirect to after verification.
    // Tokens appended as URL fragment: CallbackURL#access_token=xxx&refresh_token=xxx
    // If empty, the verify endpoint returns JSON response instead.
    CallbackURL string
}
```

## Endpoints

| Method | Path                      | Auth | Description                                |
|--------|---------------------------|------|--------------------------------------------|
| POST   | `/magic-link/send`        | No   | Send magic link email                      |
| GET    | `/magic-link/verify`      | No   | Verify magic link token (from email click) |
| POST   | `/magic-link/verify-code` | No   | Verify using code (for mobile apps)        |
| POST   | `/magic-link/resend`      | No   | Resend magic link                          |

None of these routes require authentication -- the magic link token itself is the credential.

## Flow

1. User submits email to `POST /magic-link/send`
2. GoAuth generates a token and emits an event (notification module delivers the email)
3. User clicks the link -- `GET /magic-link/verify?token=xxx`
4. GoAuth verifies the token, creates or authenticates the user
5. If `CallbackURL` is set, redirects to `CallbackURL#access_token=xxx&refresh_token=xxx`
6. If `CallbackURL` is empty, returns JSON `AuthResponse`

For mobile apps, use `POST /magic-link/verify-code` with the code from the email instead of the link.

## Extensibility

### Custom Storage

The second argument to `magiclink.New()` accepts a custom `types.CoreStorage` implementation:

```go
a.Use(magiclink.New(magicLinkConfig, myCustomCoreStorage))
```

When `nil`, the module uses `deps.Storage.Core()` from the shared storage layer.

### Event-Driven Delivery

The Magic Link module emits `EventSendMagicLink` when a link needs to be sent. The Notification module subscribes to this event and delivers the email. If you need custom delivery logic, subscribe to this event with your own handler.

## Dependencies

- **Core module** (auto-registered)

:::note
Requires the Notification module for sending emails. Register it before the Magic Link module. Enable magic link delivery with `EnableMagicLinkEmail: true` in the Notification config.
:::
