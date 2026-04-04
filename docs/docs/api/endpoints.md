---
id: endpoints
title: API Endpoints
sidebar_label: Endpoints
sidebar_position: 1
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# API Endpoints

All paths are prefixed with your `BasePath` (default: `/auth`). Endpoints depend on which modules you register.

Every successful response is wrapped in the standard `APIResponse` envelope:

```json
{
  "data": { ... },
  "message": "optional message"
}
```

Error responses use the same envelope with an `error` field:

```json
{
  "data": {
    "code": "ERROR_CODE",
    "message": "Human-readable message"
  }
}
```

List endpoints return a `ListResponse` inside `data`:

```json
{
  "data": {
    "list": [ ... ],
    "sort_field": "created_at",
    "sort_dir": "desc",
    "total": 42
  }
}
```

---

## Core Module <small>(auto-registered)</small>

The core module is always present. It handles user registration, profile management, password flows, and verification. Login/logout/refresh are provided by either the Session or Stateless module.

<details>
<summary><code>POST</code> <code>/signup</code> — Register a new user</summary>

**Request:**
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

Only `email` (or `username`) and `password` are required. The other fields are optional.

**Success Response** `201 Created`:
```json
{
  "data": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "expires_in": 900,
    "user": {
      "id": "01961abc-...",
      "email": "user@example.com",
      "name": "John Doe",
      "first_name": "John",
      "last_name": "Doe",
      "username": "johndoe",
      "phone_number": "+1234567890",
      "active": true,
      "email_verified": false,
      "phone_number_verified": false,
      "created_at": "2025-01-01T00:00:00Z",
      "updated_at": null
    },
    "message": "User registered successfully"
  }
}
```

If the Two-Factor module is registered and the user has 2FA enabled, the response may include a `challenges` array instead of tokens (see [Two-Factor Module](#two-factor-module)).

**Error** `400`: validation errors (email already exists, password policy violation, etc.)

</details>

<details>
<summary><code>GET</code> <code>/me</code> — Get current user <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Response** `200`:
```json
{
  "data": {
    "id": "01961abc-...",
    "email": "user@example.com",
    "name": "John Doe",
    "first_name": "John",
    "last_name": "Doe",
    "username": "johndoe",
    "avatar": "https://example.com/avatar.png",
    "phone_number": "+1234567890",
    "active": true,
    "email_verified": true,
    "phone_number_verified": false,
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-15T00:00:00Z",
    "last_login_at": "2025-01-20T10:30:00Z"
  }
}
```

</details>

<details>
<summary><code>PUT</code> <code>/profile</code> — Update profile <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{
  "name": "Jane Doe",
  "phone": "+9876543210",
  "avatar": "https://example.com/new-avatar.png"
}
```

All fields are optional. `phone` is validated in E.164 format. `avatar` must be a valid URL.

**Response** `200`:
```json
{
  "data": {
    "id": "01961abc-...",
    "email": "user@example.com",
    "name": "Jane Doe",
    "phone_number": "+9876543210",
    "avatar": "https://example.com/new-avatar.png",
    "active": true,
    "email_verified": true,
    "phone_number_verified": false,
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-20T12:00:00Z"
  }
}
```

</details>

<details>
<summary><code>PUT</code> <code>/change-password</code> — Change password <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{
  "old_password": "OldPassword123!",
  "new_password": "NewPassword456!"
}
```

Both fields are required. New password must be at least 8 characters and different from the old password.

**Response** `200`:
```json
{
  "data": {
    "message": "Password changed successfully"
  }
}
```

</details>

<details>
<summary><code>POST</code> <code>/is-available</code> — Check availability</summary>

Check whether an email, username, or phone number is already taken. Provide exactly **one** of the three fields.

**Request (email):**
```json
{"email": "newuser@example.com"}
```

**Request (username):**
```json
{"username": "johndoe"}
```

**Request (phone):**
```json
{"phone": "+1234567890"}
```

**Response** `200`:
```json
{
  "data": {
    "available": true,
    "field": "email",
    "message": "email is available"
  }
}
```

</details>

<details>
<summary><code>POST</code> <code>/forgot-password</code> — Request password reset</summary>

**Request:**
```json
{"email": "user@example.com"}
```

Or by phone:
```json
{"phone": "+1234567890"}
```

**Response** `200`:
```json
{
  "data": {
    "message": "Password reset email sent"
  }
}
```

</details>

<details>
<summary><code>POST</code> <code>/reset-password</code> — Reset password with token or code</summary>

**Request (token-based, from email link):**
```json
{
  "token": "reset-token-from-email",
  "email": "user@example.com",
  "new_password": "NewPassword456!"
}
```

**Request (code-based, from SMS):**
```json
{
  "code": "123456",
  "phone": "+1234567890",
  "new_password": "NewPassword456!"
}
```

Either `token` or `code` is required, along with the corresponding `email` or `phone`.

**Response** `200`:
```json
{
  "data": {
    "message": "Password reset successfully"
  }
}
```

</details>

<details>
<summary><code>POST</code> <code>/send-verification-email</code> — Send verification email</summary>

**Request:**
```json
{"email": "user@example.com"}
```

**Response** `200`:
```json
{
  "data": {
    "message": "Verification email sent"
  }
}
```

</details>

<details>
<summary><code>POST</code> <code>/resend-verification-email</code> — Resend verification email</summary>

**Request:**
```json
{"email": "user@example.com"}
```

Same as `/send-verification-email` but intended for resend flows.

</details>

<details>
<summary><code>GET</code> <code>/verify-email?token=...&email=...</code> — Verify email</summary>

Called from the email verification link. Redirects to `FrontendConfig.VerifyEmailCallbackPath` with `?status=success` or `?status=error`.

Falls back to a JSON response if `FrontendConfig` is not set.

</details>

<details>
<summary><code>POST</code> <code>/send-verification-phone</code> — Send phone verification SMS</summary>

**Request:**
```json
{"phone": "+1234567890"}
```

Requires the Notification module with an SMS sender configured.

</details>

<details>
<summary><code>POST</code> <code>/resend-verification-phone</code> — Resend phone verification SMS</summary>

**Request:**
```json
{"phone": "+1234567890"}
```

</details>

<details>
<summary><code>POST</code> <code>/verify-phone</code> — Verify phone number</summary>

**Request:**
```json
{
  "phone": "+1234567890",
  "code": "123456"
}
```

Code must be exactly 6 digits.

**Response** `200`:
```json
{
  "data": {
    "message": "Phone number verified successfully"
  }
}
```

</details>

---

## Session Module

:::info
Requires `session.New(...)`. Mutually exclusive with the Stateless module.
:::

<details>
<summary><code>POST</code> <code>/login</code> — Login (create session)</summary>

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

Or login by username:
```json
{
  "username": "johndoe",
  "password": "SecurePassword123!"
}
```

**Success Response** `200`:
```json
{
  "data": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "expires_in": 900,
    "user": {
      "id": "01961abc-...",
      "email": "user@example.com",
      "name": "John Doe",
      "active": true,
      "email_verified": true,
      "phone_number_verified": false,
      "created_at": "2025-01-01T00:00:00Z",
      "updated_at": "2025-01-15T00:00:00Z"
    },
    "message": "Login successful"
  }
}
```

If the Two-Factor module is registered and the user has 2FA enabled, the response will contain a `challenges` array instead of tokens:

```json
{
  "data": {
    "user": { ... },
    "challenges": [
      {
        "type": "2fa",
        "data": {
          "requires_2fa": true,
          "temp_token": "eyJhbGciOi...",
          "user_id": "01961abc-...",
          "message": "Two-factor authentication required. Please provide your 2FA code."
        }
      }
    ],
    "message": "Login requires additional verification"
  }
}
```

</details>

<details>
<summary><code>POST</code> <code>/logout</code> — Logout (end session) <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Ends the current session.

**Response** `200`:
```json
{
  "data": {
    "message": "Logged out successfully"
  }
}
```

</details>

<details>
<summary><code>POST</code> <code>/refresh</code> — Refresh tokens</summary>

**Request:**
```json
{"refresh_token": "eyJhbGciOi..."}
```

**Response** `200`:
```json
{
  "data": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "expires_in": 900,
    "message": "Token refreshed successfully"
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/sessions</code> — List sessions <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Returns all active sessions for the authenticated user.

**Response** `200`:
```json
{
  "data": [
    {
      "id": "sess-01961abc-...",
      "user_agent": "Mozilla/5.0...",
      "ip_address": "192.168.1.1",
      "created_at": "2025-01-01T00:00:00Z",
      "expires_at": "2025-01-02T00:00:00Z",
      "current": true
    },
    {
      "id": "sess-01961def-...",
      "user_agent": "Chrome/120...",
      "ip_address": "10.0.0.1",
      "created_at": "2025-01-01T12:00:00Z",
      "expires_at": "2025-01-02T12:00:00Z",
      "current": false
    }
  ]
}
```

</details>

<details>
<summary><code>GET</code> <code>/sessions/&#123;session_id&#125;</code> — Get session <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Returns details for a specific session.

**Response** `200`:
```json
{
  "data": {
    "id": "sess-01961abc-...",
    "user_agent": "Mozilla/5.0...",
    "ip_address": "192.168.1.1",
    "created_at": "2025-01-01T00:00:00Z",
    "expires_at": "2025-01-02T00:00:00Z",
    "current": false
  }
}
```

</details>

<details>
<summary><code>DELETE</code> <code>/sessions/&#123;session_id&#125;</code> — Revoke session <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Revokes a specific session by ID.

**Response** `200`:
```json
{
  "data": {
    "message": "Session revoked successfully"
  }
}
```

</details>

<details>
<summary><code>DELETE</code> <code>/sessions</code> — Revoke all sessions <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Revokes all sessions except the current one.

**Response** `200`:
```json
{
  "data": {
    "message": "All other sessions revoked"
  }
}
```

</details>

---

## Stateless Module

:::info
Default if no auth module is registered. Or register explicitly with `stateless.New(...)`. Mutually exclusive with Session module.
:::

<details>
<summary><code>POST</code> <code>/login</code> — Login (JWT tokens)</summary>

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

Or login by username:
```json
{
  "username": "johndoe",
  "password": "SecurePassword123!"
}
```

**Success Response** `200`:
```json
{
  "data": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "expires_in": 900,
    "user": {
      "id": "01961abc-...",
      "email": "user@example.com",
      "name": "John Doe",
      "active": true,
      "email_verified": true,
      "phone_number_verified": false,
      "created_at": "2025-01-01T00:00:00Z",
      "updated_at": "2025-01-15T00:00:00Z"
    },
    "message": "Login successful"
  }
}
```

If the Two-Factor module is registered and the user has 2FA enabled, the response includes `challenges` instead (see Session module login for shape).

</details>

<details>
<summary><code>POST</code> <code>/logout</code> — Blacklist token <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Blacklists the current access token.

**Response** `200`:
```json
{
  "data": {
    "message": "Logged out successfully"
  }
}
```

</details>

<details>
<summary><code>POST</code> <code>/refresh</code> — Refresh tokens</summary>

**Request:**
```json
{"refresh_token": "eyJhbGciOi..."}
```

Returns a new access token. If `RefreshTokenRotation: true` (the default), a new refresh token is also issued and the old one is invalidated.

**Response** `200`:
```json
{
  "data": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "expires_in": 900,
    "message": "Token refreshed successfully"
  }
}
```

</details>

---

## Two-Factor Module

:::info
Requires `twofactor.New(...)`.
:::

<details>
<summary><code>POST</code> <code>/2fa/setup</code> — Start 2FA setup <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Generates a TOTP secret, QR code URL, and backup codes. The user must verify with a code before 2FA is enabled.

**Response** `200`:
```json
{
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "qr_url": "otpauth://totp/GoAuth:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GoAuth",
    "backup_codes": ["A1B2C3D4", "E5F6G7H8", "..."],
    "message": "Scan the QR code with your authenticator app, then verify with a code to enable 2FA"
  }
}
```

</details>

<details>
<summary><code>POST</code> <code>/2fa/verify</code> — Verify and enable 2FA <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Verifies a TOTP code against the pending secret and enables 2FA.

**Request:**
```json
{"code": "123456"}
```

**Response** `200`:
```json
{
  "data": {
    "message": "Two-factor authentication enabled successfully"
  }
}
```

</details>

<details>
<summary><code>POST</code> <code>/2fa/disable</code> — Disable 2FA <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires a current TOTP code for verification before disabling.

**Request:**
```json
{"code": "123456"}
```

**Response** `200`:
```json
{
  "data": {
    "message": "Two-factor authentication disabled successfully"
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/2fa/status</code> — Get 2FA status <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Response** `200`:
```json
{
  "data": {
    "enabled": true,
    "method": "totp"
  }
}
```

When 2FA is not enabled, `method` is an empty string.

</details>

<details>
<summary><code>POST</code> <code>/2fa/verify-login</code> — Complete login with 2FA</summary>

Called after login returns a `challenges` array with `type: "2fa"`. No auth header required -- uses `temp_token` from the challenge data.

**Request:**
```json
{
  "temp_token": "eyJhbGciOi...",
  "code": "123456"
}
```

The `code` can be a TOTP code or a backup code.

**Success Response** `200`:
```json
{
  "data": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "user": {
      "id": "01961abc-...",
      "email": "user@example.com"
    }
  }
}
```

</details>

---

## OAuth Module

:::info
Requires `oauth.New(...)` with configured providers and `APIURL` set in config.
:::

<details>
<summary><code>GET</code> <code>/oauth/&#123;provider&#125;</code> — Start OAuth flow</summary>

Redirects the user to the OAuth provider's consent screen.

**Supported providers:** `google`, `github`, `facebook`, `microsoft`, `apple`, `discord`

</details>

<details>
<summary><code>GET</code> <code>/oauth/&#123;provider&#125;/callback</code> — OAuth callback</summary>

Handles the provider callback. Creates or links the user account, then:
- Redirects to `DefaultRedirectURL` with tokens in the URL fragment: `#access_token=xxx&refresh_token=xxx`
- Or returns a JSON response if no redirect URL is configured:

```json
{
  "data": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "expires_in": 900,
    "token_type": "Bearer",
    "user": {
      "id": "01961abc-...",
      "email": "user@gmail.com",
      "name": "John Doe",
      "first_name": "John",
      "last_name": "Doe",
      "avatar": "https://lh3.googleusercontent.com/...",
      "email_verified": true,
      "active": true,
      "created_at": "2025-01-01T00:00:00Z"
    },
    "is_new_user": false,
    "provider": "google"
  }
}
```

</details>

<details>
<summary><code>DELETE</code> <code>/oauth/&#123;provider&#125;</code> — Unlink provider <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Unlinks an OAuth provider from the user's account.

**Response** `200`:
```json
{
  "data": {
    "message": "Provider unlinked successfully"
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/oauth/providers</code> — List available providers</summary>

**Response** `200`:
```json
{
  "data": {
    "providers": [
      {"name": "google", "enabled": true},
      {"name": "github", "enabled": true}
    ]
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/oauth/linked</code> — List linked providers <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Response** `200`:
```json
{
  "data": {
    "providers": ["google", "github"]
  }
}
```

</details>

---

## Admin Module

:::info
Requires `admin.New(...)`. All routes require auth + admin middleware.
:::

<details>
<summary><code>GET</code> <code>/admin/users</code> — List users <span className="badge badge--danger">Admin</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Query Parameters:**

| Param | Default | Description |
|-------|---------|-------------|
| `offset` | `0` | Number of records to skip |
| `limit` | `20` | Max records to return (max 100) |
| `sort_field` | `created_at` | Sort by: `created_at`, `email`, `username`, `name` |
| `sort_dir` | `desc` | Sort direction: `asc` or `desc` |
| `query` | | Search by name, email, or username |

**Response** `200`:
```json
{
  "data": {
    "list": [
      {
        "id": "01961abc-...",
        "email": "user@example.com",
        "name": "John Doe",
        "first_name": "John",
        "last_name": "Doe",
        "username": "johndoe",
        "avatar": "",
        "phone_number": "+1234567890",
        "active": true,
        "email_verified": true,
        "phone_number_verified": false,
        "is_super_admin": false,
        "token_version": 1,
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2025-01-15T00:00:00Z",
        "last_login_at": "2025-01-20T10:30:00Z"
      }
    ],
    "sort_field": "created_at",
    "sort_dir": "desc",
    "total": 42
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/admin/users/&#123;id&#125;</code> — Get user <span className="badge badge--danger">Admin</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Returns full user details including admin-only fields (`is_super_admin`, `token_version`).

**Response** `200`:
```json
{
  "data": {
    "id": "01961abc-...",
    "email": "user@example.com",
    "name": "John Doe",
    "first_name": "John",
    "last_name": "Doe",
    "username": "johndoe",
    "avatar": "",
    "phone_number": "+1234567890",
    "active": true,
    "email_verified": true,
    "phone_number_verified": false,
    "is_super_admin": false,
    "token_version": 1,
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-15T00:00:00Z",
    "last_login_at": "2025-01-20T10:30:00Z"
  }
}
```

</details>

<details>
<summary><code>PUT</code> <code>/admin/users/&#123;id&#125;</code> — Update user <span className="badge badge--danger">Admin</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

All fields are optional (use JSON `null` or omit). At least one field must be provided.

**Request:**
```json
{
  "first_name": "Jane",
  "last_name": "Smith",
  "name": "Jane Smith",
  "email": "jane@example.com",
  "username": "janesmith",
  "avatar": "https://example.com/avatar.png",
  "phone_number": "+9876543210",
  "active": false,
  "email_verified": true,
  "phone_number_verified": false,
  "is_super_admin": false
}
```

**Response** `200`:
```json
{
  "data": {
    "message": "User updated successfully"
  }
}
```

</details>

<details>
<summary><code>DELETE</code> <code>/admin/users/&#123;id&#125;</code> — Delete user <span className="badge badge--danger">Admin</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Permanently deletes the user.

**Response** `200`:
```json
{
  "data": {
    "message": "User deleted successfully"
  }
}
```

</details>

---

## Audit Module

:::info
Requires `audit.New(...)`.
:::

### User self-service routes

<details>
<summary><code>GET</code> <code>/me/audit</code> — My audit logs <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Query Parameters:**

| Param | Default | Description |
|-------|---------|-------------|
| `offset` | `0` | Number of records to skip |
| `limit` | `20` | Max records to return (max 100) |
| `sort_field` | `created_at` | Sort by: `created_at`, `action`, `severity`, `actor_id` |
| `sort_dir` | `desc` | Sort direction: `asc` or `desc` |

**Response** `200`:
```json
{
  "data": {
    "list": [
      {
        "id": "01961abc-...",
        "action": "auth.login.success",
        "actor_id": "01961abc-...",
        "actor_type": "user",
        "severity": "info",
        "details": "Action: auth.login.success",
        "metadata": "{...}",
        "ip_address": "192.168.1.1",
        "user_agent": "Mozilla/5.0...",
        "created_at": "2025-01-20T10:30:00Z"
      }
    ],
    "sort_field": "created_at",
    "sort_dir": "desc",
    "total": 15
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/me/audit/logins</code> — My login history <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Returns login-related audit events for the authenticated user. Same query parameters and response shape as `/me/audit`.

</details>

<details>
<summary><code>GET</code> <code>/me/audit/changes</code> — My profile changes <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Returns profile update events. Same query parameters and response shape as `/me/audit`.

</details>

<details>
<summary><code>GET</code> <code>/me/audit/security</code> — My security events <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Returns security-related events (2FA changes, password changes, etc.). Same query parameters and response shape as `/me/audit`.

</details>

### Admin audit routes

<details>
<summary><code>GET</code> <code>/admin/audit</code> — All audit logs <span className="badge badge--danger">Admin</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Returns all audit logs across all users. Same query parameters and response shape as `/me/audit`.

</details>

<details>
<summary><code>GET</code> <code>/admin/audit/users/&#123;id&#125;</code> — User audit logs <span className="badge badge--danger">Admin</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Returns audit logs for a specific user. Same query parameters and response shape as `/me/audit`.

</details>

<details>
<summary><code>GET</code> <code>/admin/audit/actions/&#123;action&#125;</code> — Logs by action <span className="badge badge--danger">Admin</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Returns audit logs filtered by action type (e.g., `auth.login.success`, `auth.password.changed`). Same query parameters and response shape as `/me/audit`.

</details>

<details>
<summary><code>POST</code> <code>/admin/audit/cleanup</code> — Cleanup old logs <span className="badge badge--danger">Admin</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Triggers manual cleanup of old audit logs based on retention policy.

**Response** `200`:
```json
{
  "data": {
    "message": "Audit logs cleaned up successfully"
  }
}
```

</details>

---

## Magic Link Module

:::info
Requires `magiclink.New(...)` and the Notification module.
:::

<details>
<summary><code>POST</code> <code>/magic-link/send</code> — Send magic link</summary>

**Request:**
```json
{"email": "user@example.com"}
```

Sends an email with a magic link. If `AutoRegister: true`, creates a new user if the email does not exist.

**Response** `200`:
```json
{
  "data": {
    "message": "Magic link sent"
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/magic-link/verify?token=...</code> — Verify magic link</summary>

Called from the email link. Verifies the token and either:
- Redirects to `CallbackURL` with tokens in the URL fragment: `#access_token=xxx&refresh_token=xxx`
- Or returns a JSON auth response if no callback URL is configured

</details>

<details>
<summary><code>POST</code> <code>/magic-link/verify-code</code> — Verify by code</summary>

For mobile apps -- verifies using the numeric code from the email.

**Request:**
```json
{"email": "user@example.com", "code": "123456"}
```

**Response** `200`:
```json
{
  "data": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "expires_in": 900,
    "user": {
      "id": "01961abc-...",
      "email": "user@example.com"
    }
  }
}
```

</details>

<details>
<summary><code>POST</code> <code>/magic-link/resend</code> — Resend magic link</summary>

**Request:**
```json
{"email": "user@example.com"}
```

**Response** `200`:
```json
{
  "data": {
    "message": "Magic link sent"
  }
}
```

</details>

---

## CSRF Module

:::info
Requires `csrf.New(...)`.
:::

<details>
<summary><code>GET</code> <code>/csrf-token</code> — Get CSRF token</summary>

**Response** `200`:
```json
{
  "data": {
    "csrf_token": "hmac-signed-token"
  }
}
```

Also sets a cookie (default name: `__goauth_csrf`) with `HttpOnly: false` so client JavaScript can read it.

Include the token in the `X-CSRF-Token` header for state-changing requests (POST, PUT, DELETE, PATCH). The CSRF middleware validates the header token against the cookie automatically.

</details>

---

## Organization Module

:::info
Requires `organization.New(...)`.
:::

### User-level routes (no org context)

<details>
<summary><code>POST</code> <code>/org</code> — Create organization <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{
  "name": "Acme Inc",
  "slug": "acme-inc"
}
```

`slug` is optional -- auto-generated from name if omitted. Must be lowercase alphanumeric with hyphens, 2-64 characters.

**Response** `201`:
```json
{
  "data": {
    "id": "01961abc-...",
    "name": "Acme Inc",
    "slug": "acme-inc",
    "owner_id": "01961abc-...",
    "active": true,
    "created_at": "2025-01-01T00:00:00Z"
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/org/my</code> — List my organizations <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Returns all organizations the authenticated user is a member of.

**Response** `200`:
```json
{
  "data": [
    {
      "id": "01961abc-...",
      "name": "Acme Inc",
      "slug": "acme-inc",
      "owner_id": "01961abc-...",
      "active": true,
      "created_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```

</details>

<details>
<summary><code>POST</code> <code>/org/switch</code> — Switch active organization <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Switches the active organization context. Returns new tokens with the organization claims embedded.

**Request:**
```json
{"org_id": "01961abc-..."}
```

**Response** `200`:
```json
{
  "data": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi..."
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/org/my/invitations</code> — My pending invitations <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Returns pending invitations for the authenticated user.

**Response** `200`:
```json
{
  "data": [
    {
      "id": "01961abc-...",
      "org_id": "01961def-...",
      "email": "user@example.com",
      "role": "member",
      "inviter_id": "01961ghi-...",
      "status": "pending",
      "expires_at": "2025-01-08T00:00:00Z",
      "created_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```

</details>

<details>
<summary><code>POST</code> <code>/org/invitations/accept</code> — Accept invitation <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{"token": "invitation-token-from-email"}
```

**Response** `200`:
```json
{
  "data": {
    "id": "01961abc-...",
    "org_id": "01961def-...",
    "user_id": "01961ghi-...",
    "role": "member",
    "joined_at": "2025-01-02T00:00:00Z"
  }
}
```

</details>

<details>
<summary><code>POST</code> <code>/org/invitations/decline</code> — Decline invitation <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{"token": "invitation-token-from-email"}
```

**Response** `200`:
```json
{
  "data": {
    "message": "Invitation declined"
  }
}
```

</details>

### Org-scoped routes (require org membership)

These routes require the org auth middleware, which verifies the user is a member of the specified organization.

<details>
<summary><code>GET</code> <code>/org/&#123;orgId&#125;</code> — Get organization <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Response** `200`:
```json
{
  "data": {
    "id": "01961abc-...",
    "name": "Acme Inc",
    "slug": "acme-inc",
    "owner_id": "01961abc-...",
    "logo_url": "https://example.com/logo.png",
    "metadata": "{\"plan\": \"pro\"}",
    "active": true,
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-15T00:00:00Z"
  }
}
```

</details>

<details>
<summary><code>PUT</code> <code>/org/&#123;orgId&#125;</code> — Update organization <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

At least one field must be provided.

**Request:**
```json
{
  "name": "Acme Corp",
  "logo_url": "https://example.com/new-logo.png",
  "metadata": "{\"plan\": \"enterprise\"}"
}
```

**Response** `200`:
```json
{
  "data": {
    "id": "01961abc-...",
    "name": "Acme Corp",
    "slug": "acme-inc",
    "owner_id": "01961abc-...",
    "logo_url": "https://example.com/new-logo.png",
    "metadata": "{\"plan\": \"enterprise\"}",
    "active": true,
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-20T12:00:00Z"
  }
}
```

</details>

<details>
<summary><code>DELETE</code> <code>/org/&#123;orgId&#125;</code> — Delete organization <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Permanently deletes the organization. Requires owner role.

**Response** `200`:
```json
{
  "data": {
    "message": "Organization deleted"
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/org/&#123;orgId&#125;/members</code> — List members <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Response** `200`:
```json
{
  "data": [
    {
      "id": "01961abc-...",
      "org_id": "01961def-...",
      "user_id": "01961ghi-...",
      "role": "owner",
      "joined_at": "2025-01-01T00:00:00Z",
      "user": {
        "id": "01961ghi-...",
        "name": "John Doe",
        "email": "john@example.com",
        "username": "johndoe",
        "avatar": "",
        "active": true,
        "email_verified": true,
        "created_at": "2025-01-01T00:00:00Z"
      }
    }
  ]
}
```

</details>

<details>
<summary><code>GET</code> <code>/org/&#123;orgId&#125;/members/&#123;userId&#125;</code> — Get member <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Returns a specific member with their user details. Same shape as a single item in the list above.

</details>

<details>
<summary><code>PUT</code> <code>/org/&#123;orgId&#125;/members/&#123;userId&#125;</code> — Update member role <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{"role": "admin"}
```

Valid roles: `owner`, `admin`, `member`.

**Response** `200`:
```json
{
  "data": {
    "message": "Member role updated"
  }
}
```

</details>

<details>
<summary><code>DELETE</code> <code>/org/&#123;orgId&#125;/members/&#123;userId&#125;</code> — Remove member <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Response** `200`:
```json
{
  "data": {
    "message": "Member removed"
  }
}
```

</details>

<details>
<summary><code>POST</code> <code>/org/&#123;orgId&#125;/invite</code> — Invite member <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{
  "email": "newmember@example.com",
  "role": "member"
}
```

`role` is optional (defaults to `member`). Valid values: `owner`, `admin`, `member`.

**Response** `201`:
```json
{
  "data": {
    "id": "01961abc-...",
    "org_id": "01961def-...",
    "email": "newmember@example.com",
    "role": "member",
    "inviter_id": "01961ghi-...",
    "status": "pending",
    "expires_at": "2025-01-08T00:00:00Z",
    "created_at": "2025-01-01T00:00:00Z"
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/org/&#123;orgId&#125;/invitations</code> — List invitations <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Returns all invitations for the organization.

**Response** `200`:
```json
{
  "data": [
    {
      "id": "01961abc-...",
      "org_id": "01961def-...",
      "email": "newmember@example.com",
      "role": "member",
      "inviter_id": "01961ghi-...",
      "status": "pending",
      "expires_at": "2025-01-08T00:00:00Z",
      "created_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```

</details>

<details>
<summary><code>DELETE</code> <code>/org/&#123;orgId&#125;/invitations/&#123;invId&#125;</code> — Cancel invitation <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Response** `200`:
```json
{
  "data": {
    "message": "Invitation cancelled"
  }
}
```

</details>

---

## Authentication

Protected endpoints (marked with <span className="badge badge--primary">Auth</span>) require:

```
Authorization: Bearer <access_token>
```

Get tokens from the `/login` endpoint (Session or Stateless module). Refresh expired tokens via `/refresh`.

**Admin** endpoints (marked with <span className="badge badge--danger">Admin</span>) additionally require the `is_super_admin` flag on the user account.

**Org** endpoints (marked with <span className="badge badge--info">Org</span>) additionally require the user to be a member of the specified organization.
