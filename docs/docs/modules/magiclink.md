---
id: magiclink
title: Magic Link Module
sidebar_label: Magic Link
sidebar_position: 11
---

# Magic Link Module

Passwordless authentication via email. Users receive a link (or code) that authenticates them without a password.

## Features

- Email-based passwordless login
- Code-based verification (for mobile apps)
- Auto-registration for new emails (optional)
- Configurable token expiry
- Frontend redirect or JSON response

## Registration

```go
import "github.com/bete7512/goauth/internal/modules/magiclink"

a.Use(magiclink.New(&config.MagicLinkModuleConfig{
    TokenExpiry:  15 * time.Minute,
    AutoRegister: true,
    CallbackURL:  "http://localhost:3000/auth/magic",
}, nil))
```

## Configuration

```go
type MagicLinkModuleConfig struct {
    // Token validity (default: 15 minutes)
    TokenExpiry time.Duration

    // Create new user if email doesn't exist (default: false)
    AutoRegister bool

    // Frontend URL to redirect after verification
    // Tokens appended as URL fragment: CallbackURL#access_token=xxx&refresh_token=xxx
    // If empty, returns JSON response instead
    CallbackURL string
}
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/magic-link/send` | Send magic link email |
| GET | `/magic-link/verify` | Verify magic link token (from email click) |
| POST | `/magic-link/verify-code` | Verify using code (for mobile) |
| POST | `/magic-link/resend` | Resend magic link |

## Flow

1. User submits email to `POST /magic-link/send`
2. GoAuth sends email with magic link
3. User clicks link → `GET /magic-link/verify?token=xxx`
4. GoAuth verifies token, creates/authenticates user
5. Redirects to `CallbackURL#access_token=xxx&refresh_token=xxx`

For mobile apps, use `POST /magic-link/verify-code` with the code from the email instead.

:::note
Requires the Notification module for sending emails. Register it before the Magic Link module.
:::
