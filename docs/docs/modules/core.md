---
id: core
title: Core Module
sidebar_label: Core Module
sidebar_position: 1
---

# Core Module

The Core Module is the foundation of every GoAuth installation. It is **auto-registered** by `auth.New()` — you never register it manually via `Use()`. It owns the full user lifecycle: registration, profile management, password flows, email/phone verification, and availability checks. It does **not** handle login/logout/refresh — those are managed by the [Session](session.md) or [Stateless](stateless.md) auth module. Every other module depends on Core for user storage and authentication middleware.

## Capabilities

- **User Registration** — Email/password signup with optional username, phone, and name fields. Configurable field requirements (require username, require phone, enforce unique phone).
- **Profile Management** — View (`/me`) and update user info (name, phone, avatar). Profile data is always scoped to the authenticated user.
- **Password Reset** — Full token-based forgot/reset flow. Emits events for the Notification module to deliver reset emails automatically.
- **Password Change** — Authenticated change with old password verification. Emits events so audit and notification modules can react.
- **Email Verification** — Send, resend, and verify via secure token. Supports frontend redirect on verification. Integrates with Notification module for delivery.
- **Phone Verification** — Send, resend, and verify via OTP code. Requires the Notification module with an SMS sender configured for delivery.
- **Availability Check** — Single endpoint to check email, username, or phone availability before registration.
- **Account Lockout** — Built-in tracking of failed login attempts with configurable lockout threshold and duration (default: 5 attempts, 15-minute lockout).
- **Password Policy Enforcement** — Configurable minimum/maximum length (default: 8/128 characters).
- **Event-Driven Architecture** — Emits before/after events for every major action, enabling other modules and custom handlers to react to user lifecycle changes.

## Configuration

Core configuration is set via `Config.Core` on the top-level config. Since Core is auto-registered, there is no `Use()` call for it.

```go
a, _ := auth.New(&config.Config{
    Storage:  store,
    BasePath: "/api/v1",

    Core: &config.CoreConfig{
        RequireEmailVerification: true,
        RequirePhoneVerification: false,
        RequireUserName:          false,
        RequirePhoneNumber:       false,
        UniquePhoneNumber:        true,
    },

    Security: types.SecurityConfig{
        JwtSecretKey:  "your-secret-key-min-32-chars!!!!",
        EncryptionKey: "your-encryption-key-32-chars!",
        Session: types.SessionConfig{
            AccessTokenTTL:  15 * time.Minute,
            RefreshTokenTTL: 7 * 24 * time.Hour,
        },
    },

    FrontendConfig: &config.FrontendConfig{
        URL:                     "http://localhost:3000",
        Domain:                  "localhost",
        VerifyEmailCallbackPath: "/verify-email",
        ResetPasswordPath:       "/reset-password",
    },
})
```

### CoreConfig Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `RequireEmailVerification` | `bool` | `false` | If true, sends verification email automatically after signup |
| `RequirePhoneVerification` | `bool` | `false` | If true, sends verification SMS automatically after signup |
| `RequireUserName` | `bool` | `false` | If true, username is required during signup |
| `RequirePhoneNumber` | `bool` | `false` | If true, phone number is required during signup |
| `UniquePhoneNumber` | `bool` | `false` | If true, enforces unique phone numbers |

## Endpoints

All paths are prefixed with your `BasePath` (default: `/auth`).

### Registration

**POST** `/signup`

```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "name": "John Doe",
  "first_name": "John",
  "last_name": "Doe",
  "username": "johndoe",
  "phone_number": "+1234567890"
}
```

### Profile

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/me` | Yes | Get current user info |
| PUT | `/profile` | Yes | Update profile (name, phone, avatar) |

### Password

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/change-password` | Yes | Change password (requires old password) |
| POST | `/forgot-password` | No | Request password reset email |
| POST | `/reset-password` | No | Reset password with token |

### Verification

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/send-verification-email` | No | Send email verification link |
| POST | `/resend-verification-email` | No | Resend email verification link |
| GET | `/verify-email?token=...&email=...` | No | Verify email (redirects to frontend) |
| POST | `/send-verification-phone` | No | Send phone verification OTP |
| POST | `/resend-verification-phone` | No | Resend phone verification OTP |
| POST | `/verify-phone` | No | Verify phone with OTP code |

### Availability

**POST** `/is-available`

Check whether an email, username, or phone is available. Send exactly one field:

```json
{ "email": "user@example.com" }
```
```json
{ "username": "johndoe" }
```
```json
{ "phone": "+1234567890" }
```

Response:
```json
{
  "data": {
    "available": true,
    "field": "email",
    "message": "email is available"
  }
}
```

## Events

The Core Module emits events you can subscribe to:

```go
a.On(types.EventAfterSignup, func(ctx context.Context, e *types.Event) error {
    log.Printf("New user: %+v", e.Data)
    return nil
})
```

### Hook Events (emitted by Core)

| Category | Before | After |
|----------|--------|-------|
| Signup | `EventBeforeSignup` | `EventAfterSignup` |
| Password Change | `EventBeforeChangePassword` | `EventAfterChangePassword` |
| Profile Update | `EventBeforeChangeProfile` | `EventAfterChangeProfile` |
| Forgot Password | `EventBeforeForgotPassword` | `EventAfterForgotPassword` |
| Reset Password | `EventBeforeResetPassword` | `EventAfterResetPassword` |
| Email Verified | — | `EventAfterEmailVerified` |

### Action Events (trigger delivery via Notification module)

| Event | Description |
|-------|-------------|
| `EventSendEmailVerification` | Requests email verification delivery |
| `EventSendPhoneVerification` | Requests phone verification delivery |
| `EventSendPasswordResetEmail` | Requests password reset email delivery |

### Login/Logout Events (emitted by Session or Stateless module)

These are **not** emitted by Core, but by whichever auth module you register:

| Before | After |
|--------|-------|
| `EventBeforeLogin` | `EventAfterLogin` |
| `EventBeforeLogout` | `EventAfterLogout` |

Additional auth events: `EventAfterPasswordVerified`, `EventAuthLoginSuccess`, `EventAuthLoginFailed`.

## Data Models

### User

```go
type User struct {
    ID                  string     `json:"id"`
    Name                string     `json:"name"`
    FirstName           string     `json:"first_name"`
    LastName            string     `json:"last_name"`
    Email               string     `json:"email"`
    Username            string     `json:"username"`
    Avatar              string     `json:"avatar"`
    PhoneNumber         string     `json:"phone_number"`
    Active              bool       `json:"active"`
    EmailVerified       bool       `json:"email_verified"`
    PhoneNumberVerified bool       `json:"phone_number_verified"`
    IsSuperAdmin        bool       `json:"is_super_admin"`
    TokenVersion        int        `json:"-"`
    FailedLoginAttempts int        `json:"-"`
    LockedUntil         *time.Time `json:"-"`
    CreatedAt           time.Time  `json:"created_at"`
    LastLoginAt         *time.Time `json:"last_login_at"`
    UpdatedAt           *time.Time `json:"updated_at"`
}
```

Fields hidden from JSON (tagged `json:"-"`):
- `PasswordHash` — bcrypt hash, never exposed
- `TokenVersion` — incremented to invalidate all existing tokens for stateless revocation
- `FailedLoginAttempts` — tracks failed logins for account lockout
- `LockedUntil` — account lockout expiry timestamp

## Storage

The Core module uses the shared storage layer configured in `Config.Storage`. Since Core is auto-registered, you do not pass custom storage to it directly. Instead, configure the top-level `Storage` when creating the auth instance:

```go
store, _ := storage.NewGormStorage(storage.GormConfig{
    Dialect: types.DialectTypePostgres,
    DSN:     "host=localhost user=postgres ...",
})

a, _ := auth.New(&config.Config{
    Storage: store,
    // ...
})
```

Core accesses `Storage.Core()` which provides:
- **UserRepository** — CRUD operations on the `users` table
- **TokenRepository** — Manages verification tokens and refresh nonces
- **VerificationTokenRepository** — Manages email/phone verification tokens

To use a custom storage backend, implement the `types.Storage` interface and pass it as `Config.Storage`. All modules, including Core, will use your implementation.

## Next Steps

- [Session Module](session.md) — Server-side session auth
- [Stateless Module](stateless.md) — JWT-based stateless auth
- [Notification Module](notification.md) — Email/SMS delivery
- [API Reference](/docs/api/endpoints) — All endpoints
