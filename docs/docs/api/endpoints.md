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

---

## Core Module <small>(auto-registered)</small>

<details>
<summary><code>POST</code> <code>/signup</code> — Register a new user</summary>

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe",
  "username": "johndoe",
  "phone_number": "+1234567890",
  "extended_attributes": {"company": "Acme Inc"}
}
```

**Success Response** `200`:
```json
{
  "message": "User registered successfully",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "email_verified": false
  },
  "token": "eyJhbGciOi...",
  "refresh_token": "eyJhbGciOi..."
}
```

**Error** `400`: `"email already exists"` or validation errors.

</details>

<details>
<summary><code>GET</code> <code>/me</code> — Get current user <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Response** `200`:
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe"
}
```

</details>

<details>
<summary><code>GET</code> <code>/profile</code> — Get full profile <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Response** `200`:
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "username": "johndoe",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1234567890",
  "email_verified": true,
  "phone_number_verified": false,
  "extended_attributes": {"company": "Acme Inc"},
  "created_at": "2025-01-01T00:00:00Z",
  "updated_at": "2025-01-15T00:00:00Z"
}
```

</details>

<details>
<summary><code>PUT</code> <code>/profile</code> — Update profile <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{
  "first_name": "Jane",
  "phone_number": "+9876543210",
  "extended_attributes": {"role": "Manager"}
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

</details>

<details>
<summary><code>POST</code> <code>/forgot-password</code> — Request password reset</summary>

**Request:**
```json
{"email": "user@example.com"}
```

**Response** `200`:
```json
{"message": "Password reset email sent"}
```

</details>

<details>
<summary><code>POST</code> <code>/reset-password</code> — Reset with token</summary>

**Request:**
```json
{
  "token": "reset-token-from-email",
  "new_password": "NewPassword456!"
}
```

</details>

<details>
<summary><code>POST</code> <code>/send-verification-email</code> — Send verification email <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Sends a verification link to the user's email address.

</details>

<details>
<summary><code>GET</code> <code>/verify-email?token=...</code> — Verify email</summary>

Called from the email link. Redirects to `FrontendConfig.VerifyEmailCallbackPath` with `?status=success` or `?status=error`.

Falls back to JSON response if `FrontendConfig` is not set.

</details>

<details>
<summary><code>POST</code> <code>/send-verification-phone</code> — Send phone verification SMS <span className="badge badge--primary">Auth</span></summary>

Requires the Notification module with an SMS sender configured.

</details>

<details>
<summary><code>POST</code> <code>/verify-phone</code> — Verify phone <span className="badge badge--primary">Auth</span></summary>

**Request:**
```json
{"code": "123456"}
```

</details>

<details>
<summary><code>POST</code> <code>/availability/email</code> — Check email availability</summary>

**Request:**
```json
{"email": "newuser@example.com"}
```

**Response:**
```json
{"available": true, "field": "email"}
```

</details>

<details>
<summary><code>POST</code> <code>/availability/username</code> — Check username availability</summary>

**Request:** `{"username": "johndoe"}`

</details>

<details>
<summary><code>POST</code> <code>/availability/phone</code> — Check phone availability</summary>

**Request:** `{"phone_number": "+1234567890"}`

</details>

---

## Session Module

:::info
Requires `session.New(...)`. Mutually exclusive with Stateless.
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

**Response** `200`:
```json
{
  "message": "Login successful",
  "user": {"id": "uuid", "email": "user@example.com"},
  "token": "eyJhbGciOi...",
  "refresh_token": "eyJhbGciOi..."
}
```

</details>

<details>
<summary><code>POST</code> <code>/logout</code> — Logout <span className="badge badge--primary">Auth</span></summary>

Ends the current session.

</details>

<details>
<summary><code>POST</code> <code>/refresh</code> — Refresh tokens</summary>

**Request:**
```json
{"refresh_token": "eyJhbGciOi..."}
```

</details>

<details>
<summary><code>GET</code> <code>/sessions</code> — List sessions <span className="badge badge--primary">Auth</span></summary>

Requires `EnableSessionManagement: true`.

**Response** `200`:
```json
{
  "sessions": [
    {
      "id": "session-uuid",
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0...",
      "created_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```

</details>

<details>
<summary><code>DELETE</code> <code>/sessions/&#123;id&#125;</code> — Revoke session <span className="badge badge--primary">Auth</span></summary>

Revokes a specific session by ID.

</details>

<details>
<summary><code>DELETE</code> <code>/sessions</code> — Revoke all sessions <span className="badge badge--primary">Auth</span></summary>

Revokes all sessions except the current one.

</details>

---

## Stateless Module

:::info
Default if no auth module registered. Or register explicitly with `stateless.New(...)`.
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

**Response** `200`:
```json
{
  "message": "Login successful",
  "user": {"id": "uuid", "email": "user@example.com"},
  "token": "eyJhbGciOi...",
  "refresh_token": "eyJhbGciOi..."
}
```

</details>

<details>
<summary><code>POST</code> <code>/logout</code> — Blacklist token <span className="badge badge--primary">Auth</span></summary>

Blacklists the current access token.

</details>

<details>
<summary><code>POST</code> <code>/refresh</code> — Refresh tokens</summary>

Returns new access token. Optionally rotates refresh token if `RefreshTokenRotation: true`.

</details>

---

## Two-Factor Module

:::info
Requires `twofactor.New(...)`.
:::

<details>
<summary><code>POST</code> <code>/2fa/setup</code> — Start 2FA setup <span className="badge badge--primary">Auth</span></summary>

**Response** `200`:
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_url": "otpauth://totp/MyApp:user@example.com?secret=...",
  "backup_codes": ["12345678", "87654321", "..."]
}
```

</details>

<details>
<summary><code>POST</code> <code>/2fa/verify</code> — Verify and enable 2FA <span className="badge badge--primary">Auth</span></summary>

**Request:**
```json
{"code": "123456"}
```

</details>

<details>
<summary><code>POST</code> <code>/2fa/disable</code> — Disable 2FA <span className="badge badge--primary">Auth</span></summary>

**Request:**
```json
{"code": "123456"}
```

</details>

<details>
<summary><code>GET</code> <code>/2fa/status</code> — Get 2FA status <span className="badge badge--primary">Auth</span></summary>

**Response** `200`:
```json
{"enabled": true, "verified": true, "method": "totp"}
```

</details>

<details>
<summary><code>POST</code> <code>/2fa/verify-login</code> — Complete login with 2FA</summary>

Called after login returns `requires_2fa: true`.

**Request:**
```json
{
  "temp_token": "temporary-2fa-token",
  "code": "123456"
}
```

**Response** `200`: Returns auth tokens.

</details>

---

## OAuth Module

:::info
Requires `oauth.New(...)` with configured providers and `APIURL` set.
:::

<details>
<summary><code>GET</code> <code>/oauth/&#123;provider&#125;</code> — Start OAuth flow</summary>

Redirects to the OAuth provider's consent screen.

**Providers:** `google`, `github`, `facebook`, `microsoft`, `apple`, `discord`

</details>

<details>
<summary><code>GET</code> <code>/oauth/&#123;provider&#125;/callback</code> — OAuth callback</summary>

Handles provider callback. Creates/links user, then:
- Redirects to `DefaultRedirectURL#access_token=xxx&refresh_token=xxx`
- Or returns JSON if no redirect URL configured

</details>

<details>
<summary><code>DELETE</code> <code>/oauth/&#123;provider&#125;</code> — Unlink provider <span className="badge badge--primary">Auth</span></summary>

Unlinks an OAuth provider from the user's account.

</details>

<details>
<summary><code>GET</code> <code>/oauth/providers</code> — List available providers</summary>

**Response** `200`:
```json
{"providers": ["google", "github"]}
```

</details>

<details>
<summary><code>GET</code> <code>/oauth/linked</code> — List linked providers <span className="badge badge--primary">Auth</span></summary>

**Response** `200`:
```json
{"providers": [{"provider": "google", "email": "user@gmail.com"}]}
```

</details>

---

## Admin Module

:::info
Requires `admin.New(...)`. All routes require auth + admin middleware.
:::

<details>
<summary><code>GET</code> <code>/admin/users</code> — List users <span className="badge badge--danger">Admin</span></summary>

**Query:** `?page=1&limit=20`

**Response** `200`:
```json
{
  "users": [{"id": "uuid", "email": "user@example.com", "active": true}],
  "total": 100,
  "page": 1
}
```

</details>

<details>
<summary><code>GET</code> <code>/admin/users/&#123;id&#125;</code> — Get user <span className="badge badge--danger">Admin</span></summary>

Returns full user details.

</details>

<details>
<summary><code>PUT</code> <code>/admin/users/&#123;id&#125;</code> — Update user <span className="badge badge--danger">Admin</span></summary>

**Request:**
```json
{"active": false, "role": "admin"}
```

</details>

<details>
<summary><code>DELETE</code> <code>/admin/users/&#123;id&#125;</code> — Delete user <span className="badge badge--danger">Admin</span></summary>

Permanently deletes the user.

</details>

---

## Audit Module

:::info
Requires `audit.New(...)`.
:::

<details>
<summary><code>GET</code> <code>/me/audit</code> — My audit logs <span className="badge badge--primary">Auth</span></summary>

Returns the authenticated user's audit trail.

</details>

<details>
<summary><code>GET</code> <code>/me/audit/logins</code> — My login history <span className="badge badge--primary">Auth</span></summary>

Returns login events for the authenticated user.

</details>

<details>
<summary><code>GET</code> <code>/me/audit/changes</code> — My profile changes <span className="badge badge--primary">Auth</span></summary>

Returns profile update events.

</details>

<details>
<summary><code>GET</code> <code>/me/audit/security</code> — My security events <span className="badge badge--primary">Auth</span></summary>

Returns security-related events (2FA changes, password changes, etc.).

</details>

<details>
<summary><code>GET</code> <code>/admin/audit</code> — All audit logs <span className="badge badge--danger">Admin</span></summary>

Returns all audit logs across all users.

</details>

<details>
<summary><code>GET</code> <code>/admin/audit/users/&#123;id&#125;</code> — User audit logs <span className="badge badge--danger">Admin</span></summary>

Returns audit logs for a specific user.

</details>

<details>
<summary><code>GET</code> <code>/admin/audit/actions/&#123;action&#125;</code> — Logs by action <span className="badge badge--danger">Admin</span></summary>

Returns audit logs filtered by action type.

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
{"csrf_token": "hmac-signed-token"}
```

Also sets a `__goauth_csrf` cookie. Include the token in `X-CSRF-Token` header for protected methods (POST, PUT, DELETE, PATCH).

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

Sends an email with a magic link. If `AutoRegister: true`, creates a new user if email doesn't exist.

</details>

<details>
<summary><code>GET</code> <code>/magic-link/verify</code> — Verify magic link</summary>

**Query:** `?token=magic-link-token`

Verifies the token and either:
- Redirects to `CallbackURL#access_token=xxx&refresh_token=xxx`
- Or returns JSON auth response

</details>

<details>
<summary><code>POST</code> <code>/magic-link/verify-code</code> — Verify by code</summary>

**Request:**
```json
{"email": "user@example.com", "code": "123456"}
```

For mobile apps — verifies using the numeric code from the email.

</details>

<details>
<summary><code>POST</code> <code>/magic-link/resend</code> — Resend magic link</summary>

**Request:**
```json
{"email": "user@example.com"}
```

</details>

---

## Authentication

Protected endpoints require:

```
Authorization: Bearer <access_token>
```

Get tokens from the login endpoint. Refresh expired tokens via `/refresh`.

**Admin** endpoints additionally require admin privileges on the user account.
