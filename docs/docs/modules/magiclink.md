---
id: magiclink
title: Magic Link Module
sidebar_label: Magic Link
sidebar_position: 11
---

# Magic Link Module

Magic Link verifies an email link or a six-digit email code, then enters the same authentication completion flow as password and OAuth sign-in. It can return additional challenges instead of immediately issuing credentials.

## Registration

```go
if err := a.Use(magiclink.New(&config.MagicLinkModuleConfig{
    TokenExpiry: 10 * time.Minute,
    AutoRegister: false,
    DeliveryMode: types.MagicLinkDeliveryModeBoth,
    MaxCodeAttempts: 5,
    CallbackURL: "http://localhost:3000/auth/magic",
})); err != nil {
    return err
}
```

Import `pkg/modules/magiclink`, `pkg/config`, `pkg/types`, and `time`. The constructor takes one config argument. Use `CustomStorage` in the config for a custom `types.CoreStorage`, with the shared-store restrictions in [Custom storage](../storage.md).

## Configuration

| Field | Default | Behavior |
| --- | --- | --- |
| `TokenExpiry` | 10 minutes | Lifetime of the link/code record |
| `AutoRegister` | false | Allows creation of an account for an unknown address |
| `DeliveryMode` | `both` | `link`, `code`, or `both`, using the `MagicLinkDeliveryMode*` constants |
| `MaxCodeAttempts` | 5 | Limits failed code attempts for an issued record |
| `CallbackURL` | empty | Browser redirect after successful link verification; empty returns JSON |
| `CustomStorage` | nil | Uses shared Core storage |

## Endpoints

Prefix with `BasePath` (default `/auth`).

| Method | Path | Input |
| --- | --- | --- |
| POST | `/magic-link/send` | JSON `email` |
| POST | `/magic-link/resend` | JSON `email` |
| GET | `/magic-link/verify` | Query `token` |
| POST | `/magic-link/verify-code` | JSON `email` and `code` |

These endpoints do not require an access credential. The link or code is the email credential. Request/resend invalidates the prior record selected for that address. Code attempts are tracked in storage, and token consumption must be atomic.

```json
{"email":"user@example.com","code":"123456"}
```

## Flow

1. Send or resend creates a token/code and emits `EventSendMagicLink`.
2. A delivery handler sends the link, code, or both according to `DeliveryMode`.
3. Verification checks purpose, expiry, use state, and code-attempt limit, then consumes the token.
4. The common completer evaluates current user eligibility and interceptors.
5. If more factors are needed, the response contains `challenges` with a continuation. No final credentials are issued yet.
6. Successful completion uses the application's selected Session or Stateless strategy.

`GET /magic-link/verify` returns a challenge as JSON even when `CallbackURL` is configured. After complete authentication, cookie-only mode redirects without token fragments; bearer/both mode can put the credentials in the callback fragment. Code verification returns JSON. Credential cookies follow the shared transport settings.

## Event-Driven Delivery

Register [Notification](notification.md) with an email sender or subscribe to `EventSendMagicLink` yourself. Magic-link delivery is a required notification hook; it is not controlled by an `EnableMagicLinkEmail` config field. `EventAfterMagicLinkVerified` is emitted after successful completion.

Core is the module dependency. Register delivery handlers before initialization. For auto-registration, configure the account and verification policies intentionally; see [Security](../security.md).
