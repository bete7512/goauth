---
id: core
title: Core Module
sidebar_label: Core Module
sidebar_position: 1
---

# Core Module

The Core Module is auto-registered by `auth.New()`. It provides user management, verification, and password flows. It does **not** handle login/logout/refresh — those are managed by the [Session or Stateless](/docs/quickstart#adding-modules) auth module.

## Features

- **Registration** — Email/password signup with optional username and phone
- **Profile** — View and update user info, extended attributes (custom JSON)
- **Password Reset** — Token-based forgot/reset flow
- **Password Change** — Authenticated change with old password verification
- **Email Verification** — Send and verify via token
- **Phone Verification** — SMS-based (requires Notification module)
- **Availability** — Check email, username, phone availability

## Configuration

```go
a, _ := auth.New(&config.Config{
    Storage:     store,
    AutoMigrate: true,
    BasePath:    "/api/v1",

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

## Endpoints

All prefixed with your `BasePath`.

### Registration

**POST** `/signup`

```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe",
  "username": "johndoe",
  "phone_number": "+1234567890",
  "extended_attributes": {
    "company": "Acme Inc"
  }
}
```

### Profile

- **GET** `/me` — Current user (minimal)
- **GET** `/profile` — Full profile with extended attributes
- **PUT** `/profile` — Update profile

### Password

- **PUT** `/change-password` — Change password (authenticated)
- **POST** `/forgot-password` — Request reset email
- **POST** `/reset-password` — Reset with token

### Verification

- **POST** `/send-verification-email` — Send verification link (authenticated)
- **GET** `/verify-email?token=...` — Verify email (redirects to frontend)
- **POST** `/send-verification-phone` — Send SMS code (authenticated, requires Notification module)
- **POST** `/verify-phone` — Verify phone with code

### Availability

- **POST** `/availability/email`
- **POST** `/availability/username`
- **POST** `/availability/phone`

## Events

The Core Module emits events you can subscribe to:

```go
a.On(types.EventAfterSignup, func(ctx context.Context, e *types.Event) error {
    log.Printf("New user: %+v", e.Data)
    return nil
})
```

Available events:

| Category | Events |
|----------|--------|
| Signup | `EventBeforeSignup`, `EventAfterSignup` |
| Password | `EventBeforeForgotPassword`, `EventAfterForgotPassword`, `EventBeforePasswordChange`, `EventAfterPasswordChange` |
| Profile | `EventBeforeProfileUpdate`, `EventAfterProfileUpdate` |
| Verification | `EventBeforeEmailVerification`, `EventAfterEmailVerification`, `EventBeforePhoneVerification`, `EventAfterPhoneVerification` |

Login/logout events are emitted by the Session or Stateless module: `EventBeforeLogin`, `EventAfterLogin`, `EventAuthLoginSuccess`, `EventAuthLoginFailed`, `EventBeforeLogout`, `EventAfterLogout`.

## Data Models

### User

```go
type User struct {
    ID                    string                 `json:"id"`
    Email                 string                 `json:"email"`
    Username              *string                `json:"username,omitempty"`
    FirstName             string                 `json:"first_name"`
    LastName              string                 `json:"last_name"`
    PhoneNumber           *string                `json:"phone_number,omitempty"`
    EmailVerified         bool                   `json:"email_verified"`
    PhoneNumberVerified   bool                   `json:"phone_number_verified"`
    Active                bool                   `json:"active"`
    ExtendedAttributes    map[string]interface{} `json:"extended_attributes,omitempty"`
    CreatedAt             time.Time              `json:"created_at"`
    UpdatedAt             time.Time              `json:"updated_at"`
}
```

## Next Steps

- [Notification Module](notification.md) — Email/SMS
- [API Reference](/docs/api/endpoints) — All endpoints
