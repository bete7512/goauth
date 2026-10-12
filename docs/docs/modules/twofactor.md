---
id: twofactor
title: Two-Factor Module
sidebar_label: Two-Factor
sidebar_position: 5
---

# Two-Factor Module

Two-Factor adds TOTP and backup-code verification to the shared authentication completion flow. A login requiring another factor returns a persisted continuation, not an authenticated access token.

## Registration

```go
if err := a.Use(twofactor.New(&config.TwoFactorConfig{
    Issuer: "MyApp",
    Required: false,
    BackupCodesCount: 10,
    CodeLength: 8,
})); err != nil {
    return err
}
```

Import `pkg/modules/twofactor` and `pkg/config`. `twofactor.New()` uses issuer `GoAuth`, ten backup codes, and eight-character backup codes. Core and `Storage.TwoFactorAuth()` are required.

## How It Works

1. An authenticated user calls `POST /2fa/setup` to receive a secret, an `otpauth://` URI in `qr_url`, and backup codes.
2. The frontend renders the URI as a QR code or shows the secret.
3. `POST /2fa/verify` with a TOTP code enables the factor. Setup alone does not enable it.
4. On a later authentication, the interceptor returns a `2fa` challenge. The completer persists a five-minute transaction and adds `data.temp_token` to the challenge.
5. Send the temporary token and a TOTP or backup code to `POST /2fa/verify-login`.
6. After all required factors are satisfied, the completer atomically consumes the continuation and issues the selected session/JWT grant.

A typical challenge appears inside the normal success envelope:

```json
{
  "data": {
    "challenges": [
      {"type":"2fa","data":{"requires_2fa":true,"temp_token":"PENDING_CREDENTIAL"}}
    ]
  }
}
```

Additional envelope and challenge fields may be present. Handle the challenge array rather than expecting a top-level `requires_2fa` flag.

```json
{"temp_token":"PENDING_CREDENTIAL","code":"123456"}
```

`temp_token` is required. Supplying only `user_id` is not supported. The handler limits continuation verification attempts to ten. A consumed, expired, wrong-purpose, or version-invalidated continuation is rejected. The final response can include `access_token`, `refresh_token`, `session_id`, `expires_in`, and any remaining `challenges`.

## Endpoints

Prefix paths with `BasePath`.

| Method | Path | Credential | Purpose |
| --- | --- | --- | --- |
| POST | `/2fa/setup` | Access | Start or replace pending enrollment |
| POST | `/2fa/verify` | Access | Verify code and enable factor |
| POST | `/2fa/disable` | Access + current code | Disable factor |
| GET | `/2fa/status` | Access | Read enabled state and method |
| POST | `/2fa/verify-login` | Pending credential + code | Resume authentication |

TOTP reuse is tracked and backup codes are single-use. Store recovery codes when first shown. Repeating setup before verification replaces the pending secret and codes.

## Enforcement and Current Limits

The interceptor runs at priority 100, before the organization interceptor at 50. Challenges are honored during login, refresh, and resume. Persisted verified methods allow a completed 2FA grant to refresh without losing its assurance.

`Required: true` rejects completion for users without an enabled factor. It does not provide an unauthenticated enrollment flow: the setup routes require an access credential. Plan enrollment before enabling this requirement. The signup hook currently logs the requirement; it does not enroll users.

The named `twofactor.verify` route middleware is currently a pass-through implementation. Do not treat its registration as per-route step-up enforcement. Login/refresh enforcement comes from the completion interceptor. The library does not currently expose a general HTTP endpoint for resolving every possible custom challenge type.

## Storage

Temporary credentials are purpose-bound signed tokens backed by hashed token records. Transaction data tracks user/version, expiry, verified methods, remaining factors, and claims. Final resumption requires aggregate `types.TransactionalStorage` so consuming the continuation and creating the credential grant commit together. See [Custom storage](../storage.md).

## Events

Setup verification and disable emit `EventAuth2FAEnabled` and `EventAuth2FADisabled`. `EventAuth2FAVerified` exists, but the normal shared-completer resume branch returns before the legacy handler emission; do not assume it fires for every completed login. Durable completion can emit `authentication.completed` when configured.

Subscribe to enabled/disabled events with `a.On` before initialization to send your own alerts. The Notification module has no `Enable2FANotifications` option or built-in subscription to these events.
