---
id: endpoints
title: API Endpoints
sidebar_label: Endpoints
sidebar_position: 1
---

# API Endpoints

All paths are prefixed with your `BasePath` (default: `/auth`). Endpoints depend on which modules you register. These examples describe the current checkout. Timestamps and token strings are illustrative; fields omitted by a DTO may be absent. The OpenAPI document generated from your initialized instance is available through the [Auth API](api-auth) when enabled.

Most JSON responses use the standard `APIResponse` envelope. OAuth redirects and the raw JWKS response are exceptions:

```json
{
  "data": { ... },
  "message": "optional message"
}
```

Handler errors use the response status and structured fields inside `data`. Runtime guards (such as unavailable authentication or admission exhaustion) can return plain-text `503` responses:

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

Signup only creates the user; it does not issue credentials. Complete any required contact verification, then authenticate using `/login` or another enabled method. The default password policy accepts 8–72 bytes without trimming or normalization.

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

Revokes all of the user’s sessions, including the current session.

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
<summary><code>POST</code> <code>/logout</code> — Revoke user credentials <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Increments the user’s token version and deletes their stored token records. This invalidates existing credentials for that user across devices; it is not a single-token blacklist.

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

Returns new access and refresh credentials after conditionally consuming the stored nonce. Rotation is always applied by the current service, including when the legacy `RefreshTokenRotation` flag is false. Reusing the old refresh credential fails.

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

The `code` can be a TOTP code or a backup code. `temp_token` is required and is bound to a persisted, expiring `2fa_pending` continuation. Attempts are counted; successful completion consumes the continuation atomically. It cannot be used as an access token.

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

**Built-in provider types:** `google`, `github`, `microsoft`, `discord`. The `{provider}` segment is a configured connection ID; a named connection can select a type with `OAuthProviderConfig.Type`. Microsoft requires an explicit tenant UUID.

</details>

<details>
<summary><code>GET</code> <code>/oauth/&#123;provider&#125;/callback</code> — OAuth callback</summary>

The callback requires the matching one-use state and browser binding cookie from the start endpoint. It verifies the provider identity, applies account-linking policy, and runs shared completion. A 2FA challenge returns JSON without redirecting or issuing final credentials. A completed flow:

- Redirects to `DefaultRedirectURL`; cookie-only mode omits token fragments, while bearer/both modes include them.
- Returns JSON when no redirect URL is configured:

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


## SAML Module

:::info
Requires `saml.New(...)` with at least one connection, `oauth.New(nil)` (owner of the shared `accounts` table) and `APIURL` set in config. `{provider}` is the connection name from `SAMLModuleConfig.Providers`.
:::

<details>
<summary><code>GET</code> <code>/saml/providers</code> — List SAML connections</summary>

**Response** `200`:
```json
{
  "data": {
    "providers": [
      {
        "name": "keycloak",
        "login_url": "http://localhost:8080/auth/saml/keycloak/login",
        "metadata_url": "http://localhost:8080/auth/saml/keycloak/metadata"
      }
    ]
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/saml/&#123;provider&#125;/login</code> — Start SP-initiated login</summary>

Builds a SAML AuthnRequest (signed when `SignRequests` is on) and redirects the browser to the identity provider's single sign-on endpoint using the HTTP-Redirect binding. The request ID is sent as `RelayState` and stored in the `goauth_saml_{provider}` binding cookie. An optional `redirect_uri` query parameter must share its origin with `DefaultRedirectURL`, `ErrorRedirectURL` or `FrontendConfig.URL`.

</details>

<details>
<summary><code>POST</code> <code>/saml/&#123;provider&#125;/acs</code> — Assertion Consumer Service</summary>

Form body (`application/x-www-form-urlencoded`): `SAMLResponse` (base64 XML) and `RelayState` (the request ID; absent for IdP-initiated logins, which are refused unless `AllowIDPInitiated` is set).

The binding cookie must match `RelayState`, the stored request is consumed (one response per request), and the response's signature, issuer, audience, destination, validity window and `InResponseTo` are verified. The detailed cause of a rejection is logged, never returned. A 2FA challenge returns JSON `data.challenges`. A completed flow:

- Redirects to `redirect_uri` or `DefaultRedirectURL`; cookie-only mode omits token fragments, while bearer/both modes include them.
- Returns JSON when no redirect URL is configured:

```json
{
  "data": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "expires_in": 900,
    "token_type": "Bearer",
    "user": {
      "id": "01961abc-...",
      "email": "alice@example.com",
      "name": "Alice Liddell",
      "first_name": "Alice",
      "last_name": "Liddell",
      "email_verified": true,
      "active": true,
      "created_at": "2025-01-01T00:00:00Z"
    },
    "is_new_user": true,
    "provider": "keycloak"
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/saml/&#123;provider&#125;/metadata</code> — Service provider metadata</summary>

Returns the SP metadata document (`application/samlmetadata+xml`) with the entity ID, ACS location, requested NameID format and the SP certificate. Import it into the identity provider (Keycloak: Clients → Import client).

</details>

## Identity Provider Module

:::info
Requires `idp.New(...)` with a signing key, a consent page (`ConsentURL` or `FrontendConfig.URL`) and `APIURL` set in config. The protocol endpoints (discovery, keys, authorize, token, userinfo) speak the OpenID Connect wire format: errors are `{"error", "error_description"}` objects, not the GoAuth envelope. The admin endpoints exist only with `AdminAPI: true` and the Admin module.
:::

<details>
<summary><code>GET</code> <code>/oidc/.well-known/openid-configuration</code> — Discovery document</summary>

Public. A client library is configured with the issuer (`{APIURL}{BasePath}/oidc`) and reads the rest from here.

**Response** `200`:
```json
{
  "issuer": "https://api.example.com/auth/oidc",
  "authorization_endpoint": "https://api.example.com/auth/oidc/authorize",
  "token_endpoint": "https://api.example.com/auth/oidc/token",
  "userinfo_endpoint": "https://api.example.com/auth/oidc/userinfo",
  "jwks_uri": "https://api.example.com/auth/oidc/jwks",
  "scopes_supported": ["openid", "profile", "email", "phone", "offline_access"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "code_challenge_methods_supported": ["S256"],
  "claims_parameter_supported": false,
  "request_parameter_supported": false,
  "request_uri_parameter_supported": false,
  "authorization_response_iss_parameter_supported": true
}
```

</details>

<details>
<summary><code>GET</code> <code>/oidc/jwks</code> — Signing keys</summary>

Public. The keys that verify ID tokens, as a JSON Web Key Set. Retired keys stay listed until they lapse.

**Response** `200`:
```json
{
  "keys": [
    { "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "kXrp...", "n": "u1SU1L...", "e": "AQAB" }
  ]
}
```

</details>

<details>
<summary><code>GET</code> <code>/oidc/authorize</code> — Start a sign-in</summary>

Query parameters: `client_id`, `redirect_uri` (exactly as registered), `response_type=code`, `scope` (must contain `openid`), and optionally `state`, `nonce`, `code_challenge` with `code_challenge_method=S256`, `prompt` (`login`, `consent`, `select_account`), `max_age`, `login_hint`. PKCE is required unless the client is registered to go without.

**Response** `302` to the consent page:

```
Location: https://app.example.com/oidc/consent?request_id=3q2-7w...
```

A request whose client or redirect URI cannot be verified is never redirected to the client: it goes to `ErrorURL` when configured, and is answered `400` otherwise:

```json
{ "error": "invalid_request", "error_description": "redirect_uri is not registered for this client" }
```

Every other error goes back to the client's redirect URI as `?error=...&error_description=...&state=...&iss=...`: `invalid_scope`, `unsupported_response_type`, `invalid_request`, `request_not_supported`, `request_uri_not_supported`, and `interaction_required` for `prompt=none`.

</details>

<details>
<summary><code>POST</code> <code>/oidc/token</code> — Redeem a code or refresh token</summary>

Form body (`application/x-www-form-urlencoded`). The client authenticates with HTTP Basic or with `client_id` and `client_secret` in the form, never both; a public client sends its `client_id` only.

| Grant | Fields |
| --- | --- |
| `grant_type=authorization_code` | `code`, `code_verifier`, `redirect_uri` (required when the request used no PKCE) |
| `grant_type=refresh_token` | `refresh_token`, optional `scope` to narrow the access token |

**Response** `200` (`Cache-Control: no-store`):
```json
{
  "access_token": "kq9Xw...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6...",
  "refresh_token": "v8Hd2...",
  "scope": "openid profile email offline_access"
}
```

`refresh_token` is present only when the user approved `offline_access`. A refresh rotates the refresh token.

**Errors**: `400` `invalid_request`, `invalid_grant`, `invalid_scope`, `unsupported_grant_type`; `401` `invalid_client` with `WWW-Authenticate: Basic`.

</details>

<details>
<summary><code>GET</code> <code>/oidc/userinfo</code> — Claims about the user</summary>

`Authorization: Bearer <access_token>` with an access token from the token endpoint (not a GoAuth access token).

**Response** `200`:
```json
{
  "sub": "0198f0d2-7d3a-7c4e-9c1a-1f2e3d4c5b6a",
  "name": "Ada Lovelace",
  "preferred_username": "ada",
  "email": "ada@example.com",
  "email_verified": true
}
```

Which claims appear depends on the granted scopes. **Errors**: `401` `invalid_token`, `403` `insufficient_scope`, both also named in `WWW-Authenticate`.

</details>

<details>
<summary><code>POST</code> <code>/oidc/userinfo</code> — Claims about the user (POST)</summary>

The same as `GET`. The access token is taken from the `Authorization` header, or from an `access_token` field of a form body. A token in the URL is not accepted.

</details>

<details>
<summary><code>GET</code> <code>/oidc/consent/&#123;id&#125;</code> — Describe a pending sign-in request</summary>

Requires authentication. `{id}` is the `request_id` the consent page was opened with.

**Response** `200`:
```json
{
  "data": {
    "request_id": "3q2-7w...",
    "client": { "client_id": "grafana", "name": "Grafana", "logo_uri": "https://grafana.example.com/logo.png" },
    "redirect_host": "grafana.example.com",
    "scopes": [
      { "name": "openid", "description": "Confirm who you are", "previously_granted": false },
      { "name": "email", "description": "See your email address", "previously_granted": false }
    ],
    "consent_required": true,
    "login_required": false,
    "expires_at": "2026-11-15T10:10:00Z"
  }
}
```

`consent_required` is false when there is nothing to ask (already approved, or a `SkipConsent` client). `login_required` is true when the request asks for a newer sign-in than the user has.

**Errors**: `404` `IDP_REQUEST_NOT_FOUND` (unknown, expired or already decided).

</details>

<details>
<summary><code>POST</code> <code>/oidc/consent/&#123;id&#125;/approve</code> — Approve a sign-in request</summary>

Requires authentication. No body. The decision is single use.

**Response** `200`:
```json
{
  "data": {
    "redirect_to": "https://grafana.example.com/login/generic_oauth?code=Zp1x...&iss=https%3A%2F%2Fapi.example.com%2Fauth%2Foidc&state=af0ifjsldkj"
  }
}
```

**Errors**: `401` `IDP_LOGIN_REQUIRED` (sign in again and repeat the call; the request stays open), `404` `IDP_REQUEST_NOT_FOUND`.

</details>

<details>
<summary><code>POST</code> <code>/oidc/consent/&#123;id&#125;/deny</code> — Refuse a sign-in request</summary>

Requires authentication. No body.

**Response** `200`:
```json
{
  "data": {
    "redirect_to": "https://grafana.example.com/login/generic_oauth?error=access_denied&error_description=The+user+denied+the+request&iss=https%3A%2F%2Fapi.example.com%2Fauth%2Foidc&state=af0ifjsldkj"
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/oidc/grants</code> — List connected applications</summary>

Requires authentication. Query: `limit`, `offset`, `sort_field` (`created_at`, `last_used_at`), `sort_dir`, `client_id`.

**Response** `200`:
```json
{
  "data": {
    "list": [
      {
        "id": "0198f0d5-2b1c-7a40-8f21-6d3e9c0b7a12",
        "client_id": "grafana",
        "client_name": "Grafana",
        "scopes": ["openid", "email"],
        "created_at": "2026-11-15T10:00:00Z",
        "last_used_at": "2026-11-15T10:00:02Z"
      }
    ],
    "sort_field": "created_at",
    "sort_dir": "desc",
    "total": 1
  }
}
```

</details>

<details>
<summary><code>DELETE</code> <code>/oidc/grants/&#123;id&#125;</code> — Disconnect an application</summary>

Requires authentication. Ends the application's tokens for the user at once and removes the consent.

**Response** `200`:
```json
{ "data": { "message": "application disconnected" } }
```

**Errors**: `404` `IDP_GRANT_NOT_FOUND` (also for another user's grant).

</details>

<details>
<summary><code>GET</code> <code>/admin/oidc/clients</code> — List client applications</summary>

Requires an administrator. Query: `limit`, `offset`, `sort_field` (`created_at`, `name`, `last_used_at`), `sort_dir`, `q` (search name and client_id), `managed` (`true` for clients declared in configuration).

**Response** `200`: a `list` of clients as below (without `client_secret`), with `sort_field`, `sort_dir` and `total`.

</details>

<details>
<summary><code>POST</code> <code>/admin/oidc/clients</code> — Register a client application</summary>

Requires an administrator.

**Request**:
```json
{
  "name": "Dashboard",
  "redirect_uris": ["https://dashboard.example.com/callback"],
  "scopes": ["openid", "profile", "email"],
  "public": false,
  "require_pkce": true,
  "skip_consent": false
}
```

`client_id` is optional; one is generated when it is left out. `scopes` defaults to `openid`, `profile`, `email`.

**Response** `201`:
```json
{
  "data": {
    "id": "0198f0d2-91aa-7f0e-b6f3-0c1d2e3f4a5b",
    "client_id": "0198f0d2-91aa-7b83-a4c5-6d7e8f9a0b1c",
    "client_secret": "m3Yq0...43 characters, shown only here",
    "name": "Dashboard",
    "public": false,
    "redirect_uris": ["https://dashboard.example.com/callback"],
    "scopes": ["openid", "profile", "email"],
    "require_pkce": true,
    "skip_consent": false,
    "managed": false,
    "disabled": false,
    "created_at": "2026-11-15T10:00:00Z",
    "updated_at": "2026-11-15T10:00:00Z"
  }
}
```

**Errors**: `400` `IDP_INVALID_CLIENT`, `409` `IDP_CLIENT_EXISTS`.

</details>

<details>
<summary><code>GET</code> <code>/admin/oidc/clients/&#123;id&#125;</code> — Get a client application</summary>

Requires an administrator. `{id}` is the client's `id`, not its `client_id`. The secret is never returned. **Errors**: `404` `IDP_CLIENT_NOT_FOUND`.

</details>

<details>
<summary><code>PUT</code> <code>/admin/oidc/clients/&#123;id&#125;</code> — Replace a client application's registration</summary>

Requires an administrator. The body is the same as for registration and replaces every field; `client_id` never changes. A client that stops being public gets a secret, returned once in this response.

**Errors**: `400` `IDP_INVALID_CLIENT`, `404` `IDP_CLIENT_NOT_FOUND`, `409` `IDP_CLIENT_MANAGED` (declared in configuration).

</details>

<details>
<summary><code>DELETE</code> <code>/admin/oidc/clients/&#123;id&#125;</code> — Delete a client application</summary>

Requires an administrator. Removes the client and disconnects every user from it.

**Errors**: `404` `IDP_CLIENT_NOT_FOUND`, `409` `IDP_CLIENT_MANAGED`.

</details>

<details>
<summary><code>POST</code> <code>/admin/oidc/clients/&#123;id&#125;/secret</code> — Rotate a client secret</summary>

Requires an administrator. Returns the client with a new `client_secret`, shown only in this response. The old secret stops working at once.

**Errors**: `400` `IDP_INVALID_CLIENT` (a public client has no secret), `404` `IDP_CLIENT_NOT_FOUND`, `409` `IDP_CLIENT_MANAGED`.

</details>

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

## Invitation Module

Standalone platform invitations. For org-scoped invitations, see the Organization Module below.

### Authenticated routes

<details>
<summary><code>POST</code> <code>/invitations</code> — Send invitation <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{
  "email": "invitee@example.com",
  "purpose": "beta",
  "metadata": "{\"referral_code\": \"ABC123\"}"
}
```

`purpose` defaults to `"platform"`. `metadata` is optional.

**Response** `201`:
```json
{
  "data": {
    "id": "01961abc-...",
    "email": "invitee@example.com",
    "purpose": "beta",
    "inviter_id": "01961def-...",
    "status": "pending",
    "expires_at": "2025-01-09T00:00:00Z",
    "created_at": "2025-01-02T00:00:00Z"
  }
}
```

</details>

<details>
<summary><code>GET</code> <code>/invitations</code> — List sent invitations <span className="badge badge--primary">Auth</span></summary>

Lists invitations sent by the authenticated user. Supports `?status=pending&purpose=beta&limit=20&offset=0&sort_field=created_at&sort_dir=desc`.

</details>

<details>
<summary><code>GET</code> <code>/invitations/my</code> — My pending invitations <span className="badge badge--primary">Auth</span></summary>

Returns pending invitations for the authenticated user's email.

</details>

<details>
<summary><code>DELETE</code> <code>/invitations/&#123;invId&#125;</code> — Cancel invitation <span className="badge badge--primary">Auth</span></summary>

Only the inviter can cancel their own invitations.

</details>

### Public routes (no auth required)

<details>
<summary><code>POST</code> <code>/invitations/accept</code> — Accept invitation <span className="badge badge--success">Public</span></summary>

No authentication required. The invitation token is the authorization. If the invited email has no account, provide `name` and `password` to create one.

**Request:**
```json
{
  "token": "invitation-token-from-email",
  "name": "John Doe",
  "password": "securepassword123"
}
```

`name` and `password` are only required when the invited email has no existing account.

**Response** `200`:
```json
{
  "data": {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "user": {
      "id": "01961abc-...",
      "email": "invitee@example.com",
      "name": "John Doe",
      "email_verified": true
    },
    "is_new_user": true
  }
}
```

The invitation mutation commits before authentication completion. The response may contain `challenges` instead of final credentials when the account requires 2FA. Consume that challenge response rather than retrying the already-accepted invitation.

</details>

<details>
<summary><code>POST</code> <code>/invitations/decline</code> — Decline invitation <span className="badge badge--success">Public</span></summary>

No authentication required.

**Request:**
```json
{"token": "invitation-token-from-email"}
```

**Response** `200`:
```json
{"data": null}
```

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

Requires a verified principal and current membership in an active organization. Shared completion preserves the original authentication time and methods, and returns new credentials with `active_org_id` and `org_role`. No first organization is selected automatically and no `org_memberships` claim is added. The current switch handler rejects results that require another challenge.

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
<summary><code>POST</code> <code>/org/invitations/accept</code> — Accept org invitation <span className="badge badge--success">Public</span></summary>

No authentication required. The invitation token is the authorization. If the invited email has no account, provide `name` and `password` to create one.

**Request:**
```json
{
  "token": "invitation-token-from-email",
  "name": "John Doe",
  "password": "securepassword123"
}
```

`name` and `password` are only required when the invited email has no existing account.

**Response** `200`:
```json
{
  "data": {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "user": {
      "id": "01961abc-...",
      "email": "john@example.com",
      "name": "John Doe",
      "email_verified": true
    },
    "member": {
      "id": "01961def-...",
      "org_id": "01961ghi-...",
      "user_id": "01961abc-...",
      "role": "member",
      "joined_at": "2025-01-02T00:00:00Z"
    },
    "is_new_user": true
  }
}
```

The invitation mutation commits before authentication completion. The response may contain `challenges` instead of final credentials when the account requires 2FA. Consume that challenge response rather than retrying the already-accepted invitation.

</details>

<details>
<summary><code>POST</code> <code>/org/invitations/decline</code> — Decline org invitation <span className="badge badge--success">Public</span></summary>

No authentication required.

**Request:**
```json
{"token": "invitation-token-from-email"}
```

**Response** `200`:
```json
{
  "data": null
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

## RBAC Module

:::info
Requires `rbac.New(...)`. The `/org/{orgId}/...` routes exist only with `Organizations: true`, which also requires `organization.New(...)`. See [RBAC](../modules/rbac.md) for permissions, grants and the rule that nobody manages a role that grants more than they hold.
:::

### Own permissions and the catalog

<details>
<summary><code>GET</code> <code>/me/permissions</code> — Get my roles and permissions <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

**Query parameters:** `org_id` (optional) answers for that organization. Without it the scope is the organization the caller is signed in to, or the whole application when there is none. A caller who is not a member of the organization holds only their application-wide roles there.

`permissions` holds grant patterns; `invoice:*` allows every action on `invoice`. Rules the application attaches to single routes are not reflected.

**Response** `200`:
```json
{
  "data": {
    "user_id": "01961abc-...",
    "scope": "org",
    "org_id": "01961def-...",
    "roles": [
      { "key": "member", "name": "Member", "scope": "org", "system": true, "implied": true },
      { "key": "billing", "name": "Billing", "scope": "org", "system": false, "implied": false }
    ],
    "permissions": ["invoice:*"]
  }
}
```

**Errors:** `400` `RBAC_SCOPE_UNAVAILABLE` (organization roles are off).

</details>

<details>
<summary><code>GET</code> <code>/rbac/permissions</code> — List the permission catalog <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.roles:read` in the scope chosen as for `/me/permissions` (`org_id` query parameter, else the caller's organization, else the application). The catalog lists the permissions the application has declared so far.

**Response** `200`:
```json
{
  "data": [
    { "permission": "goauth.roles:read", "description": "See roles and the permission catalog" },
    { "permission": "invoice:approve" },
    { "permission": "invoice:read" }
  ]
}
```

**Errors:** `403` `RBAC_PERMISSION_DENIED`.

</details>

### Application-wide roles

<details>
<summary><code>GET</code> <code>/rbac/roles</code> — List application-wide roles <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.roles:read`.

**Query parameters:** `offset`, `limit` (max 100), `sort_field` (`created_at`, `key`, `name`), `sort_dir`, `query` (matches key or name).

Roles defined in code have `system: true` and no `created_at`. Sorted by creation time they come after custom roles in the default descending order.

**Response** `200`:
```json
{
  "data": {
    "list": [
      {
        "key": "analyst",
        "name": "Analyst",
        "description": "Reads and exports reports",
        "grants": ["report:*"],
        "scope": "global",
        "system": false,
        "implied": false,
        "created_by": "01961abc-...",
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2025-01-01T00:00:00Z"
      },
      {
        "key": "super_admin",
        "name": "Super admin",
        "description": "Every user with the super admin flag. Holds every permission everywhere.",
        "grants": ["*", "goauth.*:*"],
        "scope": "global",
        "system": true,
        "implied": true
      }
    ],
    "sort_field": "created_at",
    "sort_dir": "desc",
    "total": 2
  }
}
```

**Errors:** `403` `RBAC_PERMISSION_DENIED`.

</details>

<details>
<summary><code>POST</code> <code>/rbac/roles</code> — Create an application-wide role <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.roles:write`. Every grant must be within what the caller holds.

**Request:**
```json
{
  "key": "analyst",
  "name": "Analyst",
  "description": "Reads and exports reports",
  "grants": ["report:*"]
}
```

`key` is 1 to 64 lowercase letters, digits, `_` or `-` and cannot be changed later. `description` and `grants` are optional.

**Response** `201`:
```json
{
  "data": {
    "key": "analyst",
    "name": "Analyst",
    "description": "Reads and exports reports",
    "grants": ["report:*"],
    "scope": "global",
    "system": false,
    "implied": false,
    "created_by": "01961abc-...",
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z"
  }
}
```

**Errors:** `400` `RBAC_INVALID_ROLE`, `403` `RBAC_PERMISSION_DENIED` or `RBAC_GRANT_NOT_HELD`, `409` `RBAC_ROLE_EXISTS` or `RBAC_ROLE_SYSTEM` (reserved key), `422` `RBAC_LIMIT_EXCEEDED`.

</details>

<details>
<summary><code>GET</code> <code>/rbac/roles/&#123;roleKey&#125;</code> — Get an application-wide role <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.roles:read`.

**Response** `200`:
```json
{
  "data": {
    "key": "analyst",
    "name": "Analyst",
    "description": "Reads and exports reports",
    "grants": ["report:*"],
    "scope": "global",
    "system": false,
    "implied": false,
    "created_by": "01961abc-...",
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z"
  }
}
```

**Errors:** `403` `RBAC_PERMISSION_DENIED`, `404` `RBAC_ROLE_NOT_FOUND`.

</details>

<details>
<summary><code>PUT</code> <code>/rbac/roles/&#123;roleKey&#125;</code> — Update an application-wide role <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.roles:write`. At least one field must be provided; fields left out are kept. Both the role's current grants and the new ones must be within what the caller holds. The change applies to everyone who holds the role on their next request.

**Request:**
```json
{
  "name": "Report analyst",
  "grants": ["report:read", "report:export"]
}
```

**Response** `200`: the updated role, as for `GET`.

**Errors:** `400` `RBAC_INVALID_ROLE`, `403` `RBAC_PERMISSION_DENIED` or `RBAC_GRANT_NOT_HELD`, `404` `RBAC_ROLE_NOT_FOUND`, `409` `RBAC_ROLE_SYSTEM` (defined in code), `422` `RBAC_LIMIT_EXCEEDED`.

</details>

<details>
<summary><code>DELETE</code> <code>/rbac/roles/&#123;roleKey&#125;</code> — Delete an application-wide role <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.roles:write`. Deletes a custom role and takes it away from everyone who holds it.

**Response** `200`:
```json
{
  "data": null
}
```

**Errors:** `403` `RBAC_PERMISSION_DENIED` or `RBAC_GRANT_NOT_HELD`, `404` `RBAC_ROLE_NOT_FOUND`, `409` `RBAC_ROLE_SYSTEM`.

</details>

<details>
<summary><code>GET</code> <code>/rbac/users/&#123;userId&#125;/roles</code> — Get a user's application-wide roles <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Users may read their own roles. Reading someone else's requires `goauth.assignments:read`.

**Response** `200`:
```json
{
  "data": {
    "user_id": "01961abc-...",
    "scope": "global",
    "roles": [
      { "key": "analyst", "name": "Analyst", "scope": "global", "system": false, "implied": false }
    ],
    "permissions": ["report:*"]
  }
}
```

**Errors:** `403` `RBAC_PERMISSION_DENIED`, `404` `USER_NOT_FOUND`.

</details>

<details>
<summary><code>PUT</code> <code>/rbac/users/&#123;userId&#125;/roles</code> — Set a user's application-wide roles <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.assignments:write`. `roles` becomes the complete list of roles assigned to the user application-wide; an empty list removes them all. Every role given or taken away must be within what the caller holds.

**Request:**
```json
{
  "roles": ["analyst"]
}
```

**Response** `200`:
```json
{
  "data": {
    "user_id": "01961abc-...",
    "scope": "global",
    "roles": [
      { "key": "analyst", "name": "Analyst", "scope": "global", "system": false, "implied": false }
    ],
    "permissions": ["report:*"]
  }
}
```

**Errors:** `400` (missing `roles`), `403` `RBAC_PERMISSION_DENIED`, `RBAC_GRANT_NOT_HELD` or `RBAC_ASSIGNMENT_REFUSED`, `404` `USER_NOT_FOUND` or `RBAC_ROLE_NOT_FOUND`, `409` `RBAC_ROLE_SYSTEM` (implied role), `422` `RBAC_LIMIT_EXCEEDED`.

</details>

<details>
<summary><code>GET</code> <code>/rbac/assignments</code> — List application-wide role assignments <span className="badge badge--primary">Auth</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.assignments:read`.

**Query parameters:** `offset`, `limit` (max 100), `sort_field` (`created_at`, `role_key`, `user_id`), `sort_dir`, `user_id`, `role`.

**Response** `200`:
```json
{
  "data": {
    "list": [
      {
        "user_id": "01961abc-...",
        "role": "analyst",
        "scope": "global",
        "granted_by": "01961xyz-...",
        "created_at": "2025-01-01T00:00:00Z"
      }
    ],
    "sort_field": "created_at",
    "sort_dir": "desc",
    "total": 1
  }
}
```

**Errors:** `403` `RBAC_PERMISSION_DENIED`.

</details>

### Organization roles

The permission must be held in the organization named in the path. A user with an application-wide role that carries it, such as a super admin, is allowed in every organization.

<details>
<summary><code>GET</code> <code>/org/&#123;orgId&#125;/roles</code> — List an organization's roles <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.roles:read`. Lists the membership roles (`owner`, `admin`, `member`), the roles defined in code and the organization's custom roles.

**Query parameters:** `offset`, `limit` (max 100), `sort_field` (`created_at`, `key`, `name`), `sort_dir`, `query`.

**Response** `200`:
```json
{
  "data": {
    "list": [
      {
        "key": "admin",
        "name": "Admin",
        "description": "Organization members with the admin role.",
        "grants": ["*", "goauth.assignments:read", "goauth.roles:read"],
        "scope": "org",
        "org_id": "01961def-...",
        "system": true,
        "implied": true
      },
      {
        "key": "billing",
        "name": "Billing",
        "description": "Handles invoices",
        "grants": ["invoice:*"],
        "scope": "org",
        "org_id": "01961def-...",
        "system": false,
        "implied": false,
        "created_by": "01961abc-...",
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2025-01-01T00:00:00Z"
      }
    ],
    "sort_field": "key",
    "sort_dir": "asc",
    "total": 4
  }
}
```

The example shows two of the four roles, as returned for `sort_field=key&sort_dir=asc`.

**Errors:** `403` `RBAC_PERMISSION_DENIED`, `404` `ORG_NOT_FOUND`.

</details>

<details>
<summary><code>POST</code> <code>/org/&#123;orgId&#125;/roles</code> — Create a role in an organization <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.roles:write`. Every grant must be within what the caller holds in the organization. The role exists in this organization only.

**Request:**
```json
{
  "key": "billing",
  "name": "Billing",
  "description": "Handles invoices",
  "grants": ["invoice:*"]
}
```

**Response** `201`:
```json
{
  "data": {
    "key": "billing",
    "name": "Billing",
    "description": "Handles invoices",
    "grants": ["invoice:*"],
    "scope": "org",
    "org_id": "01961def-...",
    "system": false,
    "implied": false,
    "created_by": "01961abc-...",
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z"
  }
}
```

**Errors:** `400` `RBAC_INVALID_ROLE`, `403` `RBAC_PERMISSION_DENIED` or `RBAC_GRANT_NOT_HELD`, `404` `ORG_NOT_FOUND`, `409` `RBAC_ROLE_EXISTS` or `RBAC_ROLE_SYSTEM` (`owner`, `admin`, `member` and `super_admin` are reserved), `422` `RBAC_LIMIT_EXCEEDED`.

</details>

<details>
<summary><code>GET</code> <code>/org/&#123;orgId&#125;/roles/&#123;roleKey&#125;</code> — Get a role of an organization <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.roles:read`.

**Response** `200`:
```json
{
  "data": {
    "key": "billing",
    "name": "Billing",
    "description": "Handles invoices",
    "grants": ["invoice:*"],
    "scope": "org",
    "org_id": "01961def-...",
    "system": false,
    "implied": false,
    "created_by": "01961abc-...",
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z"
  }
}
```

**Errors:** `403` `RBAC_PERMISSION_DENIED`, `404` `ORG_NOT_FOUND` or `RBAC_ROLE_NOT_FOUND`.

</details>

<details>
<summary><code>PUT</code> <code>/org/&#123;orgId&#125;/roles/&#123;roleKey&#125;</code> — Update a role of an organization <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.roles:write`. At least one field must be provided; fields left out are kept. Both the role's current grants and the new ones must be within what the caller holds.

**Request:**
```json
{
  "grants": ["invoice:read", "invoice:approve"]
}
```

**Response** `200`: the updated role, as for `GET`.

**Errors:** `400` `RBAC_INVALID_ROLE`, `403` `RBAC_PERMISSION_DENIED` or `RBAC_GRANT_NOT_HELD`, `404` `ORG_NOT_FOUND` or `RBAC_ROLE_NOT_FOUND`, `409` `RBAC_ROLE_SYSTEM`, `422` `RBAC_LIMIT_EXCEEDED`.

</details>

<details>
<summary><code>DELETE</code> <code>/org/&#123;orgId&#125;/roles/&#123;roleKey&#125;</code> — Delete a role of an organization <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.roles:write`. Deletes a custom role and takes it away from every member who holds it.

**Response** `200`:
```json
{
  "data": null
}
```

**Errors:** `403` `RBAC_PERMISSION_DENIED` or `RBAC_GRANT_NOT_HELD`, `404` `ORG_NOT_FOUND` or `RBAC_ROLE_NOT_FOUND`, `409` `RBAC_ROLE_SYSTEM`.

</details>

<details>
<summary><code>GET</code> <code>/org/&#123;orgId&#125;/members/&#123;userId&#125;/roles</code> — Get a member's roles in an organization <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Members may read their own roles. Reading someone else's requires `goauth.assignments:read`. The list holds the membership role, the roles assigned in the organization and any application-wide roles, which apply inside every organization.

**Response** `200`:
```json
{
  "data": {
    "user_id": "01961abc-...",
    "scope": "org",
    "org_id": "01961def-...",
    "roles": [
      { "key": "member", "name": "Member", "scope": "org", "system": true, "implied": true },
      { "key": "billing", "name": "Billing", "scope": "org", "system": false, "implied": false }
    ],
    "permissions": ["invoice:*"]
  }
}
```

**Errors:** `403` `RBAC_PERMISSION_DENIED`, `404` `ORG_NOT_FOUND` or `ORG_MEMBER_NOT_FOUND`.

</details>

<details>
<summary><code>PUT</code> <code>/org/&#123;orgId&#125;/members/&#123;userId&#125;/roles</code> — Set a member's roles in an organization <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.assignments:write`. `roles` becomes the complete list of roles assigned to the member in the organization; an empty list removes them all. The membership role is not part of the list: change it with `PUT /org/&#123;orgId&#125;/members/&#123;userId&#125;`. The roles end when the membership does.

**Request:**
```json
{
  "roles": ["billing"]
}
```

**Response** `200`:
```json
{
  "data": {
    "user_id": "01961abc-...",
    "scope": "org",
    "org_id": "01961def-...",
    "roles": [
      { "key": "member", "name": "Member", "scope": "org", "system": true, "implied": true },
      { "key": "billing", "name": "Billing", "scope": "org", "system": false, "implied": false }
    ],
    "permissions": ["invoice:*"]
  }
}
```

**Errors:** `400` (missing `roles`), `403` `RBAC_PERMISSION_DENIED`, `RBAC_GRANT_NOT_HELD` or `RBAC_ASSIGNMENT_REFUSED`, `404` `ORG_NOT_FOUND`, `ORG_MEMBER_NOT_FOUND` or `RBAC_ROLE_NOT_FOUND`, `409` `RBAC_ROLE_SYSTEM` (membership role), `422` `RBAC_LIMIT_EXCEEDED`.

</details>

<details>
<summary><code>GET</code> <code>/org/&#123;orgId&#125;/role-assignments</code> — List role assignments in an organization <span className="badge badge--primary">Auth</span> <span className="badge badge--info">Org</span></summary>

**Headers:** `Authorization: Bearer <access_token>`

Requires `goauth.assignments:read`. Membership roles are not assignments and are not listed.

**Query parameters:** `offset`, `limit` (max 100), `sort_field` (`created_at`, `role_key`, `user_id`), `sort_dir`, `user_id`, `role`.

**Response** `200`:
```json
{
  "data": {
    "list": [
      {
        "user_id": "01961abc-...",
        "role": "billing",
        "scope": "org",
        "org_id": "01961def-...",
        "granted_by": "01961xyz-...",
        "created_at": "2025-01-01T00:00:00Z"
      }
    ],
    "sort_field": "created_at",
    "sort_dir": "desc",
    "total": 1
  }
}
```

**Errors:** `403` `RBAC_PERMISSION_DENIED`, `404` `ORG_NOT_FOUND`.

</details>

---

## Public Signing Keys

<details>
<summary><code>GET</code> <code>/.well-known/jwks.json</code> — Public JWT verification keys</summary>

Returns a raw JSON Web Key Set with active and unexpired retained asymmetric public keys. It is not wrapped in `data`. An HS256-only configuration returns `404`; HMAC secrets are never published. Successful responses set a one-hour cache lifetime. See [Security](../security.md) for key rotation and custom-manager support.

</details>

## Passkeys Module

Register `passkeys.New(...)` with an RP ID and allowed origins. See [Passkeys](../modules/passkeys.md) for browser serialization and complete ceremony examples.

<details>
<summary><code>POST</code> <code>/passkeys/register/begin</code> — Begin registration (Auth)</summary>

Returns `data.challenge_token` and `data.public_key` creation options. Authenticate the existing account, then call `navigator.credentials.create` with converted options.

</details>

<details>
<summary><code>POST</code> <code>/passkeys/register/finish</code> — Finish registration (Auth)</summary>

Send `challenge_token`, optional `name`, and the actual browser-generated `credential_response` object. The record is consumed before verification, and a successful registration returns `201` with the new credential summary.

</details>

<details>
<summary><code>POST</code> <code>/passkeys/login/begin</code> — Begin discoverable login</summary>

No email or user ID is required. Returns `data.challenge_token` and `data.public_key` request options for `navigator.credentials.get`.

</details>

<details>
<summary><code>POST</code> <code>/passkeys/login/finish</code> — Finish login</summary>

Send `challenge_token` and the serialized assertion as `credential_response`. After origin, RP, identity, signature, and counter checks, shared completion returns credentials or `challenges`. Cookie transport follows `AuthMode`.

</details>

<details>
<summary><code>GET</code> <code>/passkeys</code> — List owned passkeys (Auth)</summary>

Returns an array in `data` containing `id`, `name`, `created_at`, optional `transports`, and optional `last_used_at`. The current login path does not update last-used timestamps.

</details>

<details>
<summary><code>PUT</code> <code>/passkeys/&#123;id&#125;</code> — Rename an owned passkey (Auth)</summary>

Send `{"name":"Work laptop"}`. Ownership is verified; success returns `200`.

</details>

<details>
<summary><code>DELETE</code> <code>/passkeys/&#123;id&#125;</code> — Delete an owned passkey (Auth)</summary>

Ownership is verified; success returns `200`. Deleting a passkey does not delete the user account.

</details>

Passkey finish requests are one-use and purpose-bound. A failed finish needs a new begin request. `credential_response` must be a JSON object with base64url-encoded binary fields, not a stringified object. Current challenge expiry is capped at five minutes.

---

## Authentication

Protected endpoints (marked with <span className="badge badge--primary">Auth</span>) require:

```
Authorization: Bearer <access_token>
```

This header is the bearer example. Cookie or both mode can accept the configured access cookie instead. Conflicting sources are rejected; a refresh token, pending 2FA continuation, or passkey challenge is not an access credential. Both strategies check current user/version state, and session and selected-organization state where applicable.

Get credentials from `/login` or another enabled method. Password, OAuth, magic-link, passkey, and invitation completion may return `data.challenges` instead of final tokens. Send the continuation’s `temp_token` and a factor code to `/2fa/verify-login`; a user ID alone is never sufficient. Refresh via `/refresh` using the configured transport. Cookie-only JSON responses still include token fields.

**Admin** endpoints (marked with <span className="badge badge--danger">Admin</span>) additionally require the `is_super_admin` flag on the user account.

**Org** endpoints (marked with <span className="badge badge--info">Org</span>) additionally require the user to be a member of the specified organization.
