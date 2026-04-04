---
id: twofactor
title: Two-Factor Module
sidebar_label: Two-Factor
sidebar_position: 5
---

# Two-Factor Module

The Two-Factor module adds TOTP-based two-factor authentication to your application, significantly hardening account security. When a user with 2FA enabled logs in, the login flow is intercepted via an auth interceptor — the user receives a short-lived temporary token and must complete a second verification step via `/2fa/verify-login` before receiving actual auth tokens. This works transparently with both the Session and Stateless auth modules.

## Capabilities

- **TOTP (Time-based One-Time Password)** — Compatible with any standard authenticator app (Google Authenticator, Authy, 1Password, Bitwarden, etc.). Uses the standard TOTP algorithm (RFC 6238).
- **QR Code Setup** — The `/2fa/setup` endpoint returns both the TOTP secret and a `otpauth://` URI that can be rendered as a QR code for one-scan setup.
- **Backup Codes** — Generates configurable backup codes (default: 10 codes, 8 characters each) for account recovery when the authenticator device is unavailable. Each backup code is single-use.
- **Code Reuse Prevention** — TOTP codes are tracked to prevent replay within the same time window. A code that has already been used in the current 30-second window is rejected.
- **Login Flow Interception** — Registers an auth interceptor (priority 100) that intercepts the login response when 2FA is enabled. Instead of returning auth tokens, returns `requires_2fa: true` with a temporary token (5-minute TTL).
- **Optional Enforcement** — Set `Required: true` to make 2FA mandatory for all users. New users are flagged to set up 2FA after signup.
- **Route Protection Middleware** — Registers a `twofactor.verify` middleware (priority 40) on `core.*` and `admin.*` routes, ensuring authenticated users with 2FA enabled have completed verification.
- **Disable Flow** — Users can disable 2FA via `/2fa/disable`, and check their current status via `/2fa/status`.

## Registration

```go
import (
    "github.com/bete7512/goauth/pkg/modules/twofactor"
    "github.com/bete7512/goauth/pkg/config"
)

// With custom config
a.Use(twofactor.New(&config.TwoFactorConfig{
    Issuer:           "MyApp",  // Shown in authenticator app
    Required:         false,    // Force 2FA for all users
    BackupCodesCount: 10,
    CodeLength:       8,
}))

// With defaults (Issuer:"GoAuth", 10 backup codes, length 8)
a.Use(twofactor.New())
```

The constructor is variadic -- call `twofactor.New()` with no arguments for defaults, or pass a `*config.TwoFactorConfig`.

## How It Works

1. User calls `POST /2fa/setup` -- gets secret + QR URL
2. User scans QR in authenticator app
3. User calls `POST /2fa/verify` with TOTP code -- 2FA is enabled
4. On next login, the auth interceptor fires and login returns `requires_2fa: true` + `temp_token`
5. User calls `POST /2fa/verify-login` with temp token + TOTP code -- gets auth tokens

## Endpoints

| Method | Path              | Auth | Description                        |
|--------|-------------------|------|------------------------------------|
| POST   | `/2fa/setup`      | Yes  | Start 2FA setup, returns secret + QR URL |
| POST   | `/2fa/verify`     | Yes  | Verify TOTP code, enables 2FA     |
| POST   | `/2fa/disable`    | Yes  | Disable 2FA for the current user  |
| GET    | `/2fa/status`     | Yes  | Get current 2FA status            |
| POST   | `/2fa/verify-login` | No | Complete login with temp token + TOTP code |

All authenticated routes use the `core.auth` middleware. The `/2fa/verify-login` route is unauthenticated -- it validates the short-lived temp token (5-minute TTL) issued during the 2FA challenge.

## Configuration

```go
type TwoFactorConfig struct {
    Issuer           string // App name shown in authenticator (default: "GoAuth")
    Required         bool   // Make 2FA mandatory for all users
    BackupCodesCount int    // Number of backup codes to generate (default: 10)
    CodeLength       int    // Length of each backup code (default: 8)
}
```

## Middleware

The module registers a `twofactor.verify` middleware (priority 40) that applies to `core.*` and `admin.*` routes, excluding login, signup, and `twofactor.*` routes. This middleware checks that authenticated users with 2FA enabled have completed verification in the current session.

## Events

| Event                  | Fired When              |
|------------------------|-------------------------|
| `auth.2fa.enabled`     | User enables 2FA        |
| `auth.2fa.disabled`    | User disables 2FA       |
| `auth.2fa.verified`    | User passes 2FA check   |

When `Required` is `true`, the module subscribes to `EventAfterSignup` to flag that new users must set up 2FA.

## Dependencies

- **Core module** (auto-registered)

## Extensibility

### Integration with Notification Module

When the Notification module is registered with `Enable2FANotifications: true`, 2FA-related events trigger notification delivery (e.g., email alerts when 2FA is enabled or disabled).

### Event Hooks

Subscribe to 2FA events for custom logic:

```go
a.On(types.EventAuth2FAEnabled, func(ctx context.Context, e *types.Event) error {
    // e.g., log to external security dashboard
    return nil
})
```
