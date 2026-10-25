---
id: passkeys
title: Passkeys
---

# Passkeys

> **Experimental.** This module works and is tested, but its API and schema may change during the beta.

The Passkeys module adds WebAuthn credential registration, discoverable sign-in, and credential management. A verified assertion enters GoAuth's shared completion flow, so current account policy, the selected session/JWT strategy, and additional challenges still apply.

## Registration

```go
if err := a.Use(passkeys.New(&config.PasskeysModuleConfig{
    RPDisplayName: "MyApp",
    RPID: "example.com",
    RPOrigins: []string{"https://app.example.com"},
})); err != nil {
    return err
}
```

Import `github.com/bete7512/goauth/pkg/modules/passkeys` and `pkg/config`. Register before initialization. The frontend origin must be one of the configured RP origins; the RP ID has no scheme or port.

For local development use `RPID: "localhost"` with the actual frontend origin, such as `http://localhost:3000`. Changing the RP ID changes the identity under which authenticators recognize credentials.

## Configuration

| Field | Behavior |
| --- | --- |
| `RPDisplayName` | Defaults to `GoAuth` |
| `RPID` | Required relying-party ID |
| `RPOrigins` | At least one allowed ceremony origin is required |
| `CustomStorage` | Optional `types.PasskeyStorage`; otherwise uses `Storage.Passkeys()` |
| `ChallengeTTL` | Exposed config field; current implementation caps ceremonies at five minutes and does not apply a custom value |

The built-in GORM storage implements passkey persistence, including migrations for PostgreSQL, MySQL, and SQLite. Core token storage persists one-time ceremony records.

## Endpoints

Prefix paths with `BasePath` (default `/auth`).

| Method | Path | Access auth | Purpose |
| --- | --- | --- | --- |
| POST | `/passkeys/register/begin` | Required | Return creation options and a challenge token |
| POST | `/passkeys/register/finish` | Required | Verify attestation and save the credential |
| POST | `/passkeys/login/begin` | No | Return discoverable-login request options |
| POST | `/passkeys/login/finish` | No | Verify assertion, then complete auth or return challenges |
| GET | `/passkeys` | Required | List the current user's credential summaries |
| PUT | `/passkeys/{id}` | Required | Rename an owned credential |
| DELETE | `/passkeys/{id}` | Required | Delete an owned credential |

## Browser Registration Flow

1. Authenticate the user through an existing method.
2. Call `/passkeys/register/begin` with that access credential or cookie.
3. Read `data.public_key` and `data.challenge_token` from the response.
4. Convert the JSON WebAuthn options to browser credential-creation options, including base64url binary fields, and call `navigator.credentials.create`.
5. Serialize the returned credential to WebAuthn JSON and send it with the challenge token:

```json
{
  "challenge_token": "OPAQUE_CHALLENGE",
  "name": "My security key",
  "credential_response": {
    "id": "BASE64URL_CREDENTIAL_ID",
    "rawId": "BASE64URL_CREDENTIAL_ID",
    "type": "public-key",
    "response": {
      "clientDataJSON": "BASE64URL_CLIENT_DATA",
      "attestationObject": "BASE64URL_ATTESTATION"
    }
  }
}
```

This is a payload shape, not a usable credential. Send the actual browser-generated response; `credential_response` must be a JSON object, not a JSON-encoded string. Raw `ArrayBuffer` values are not serialized correctly by an ordinary `JSON.stringify` without conversion.

## Browser Login Flow

Call `/passkeys/login/begin`, convert `data.public_key` into WebAuthn request options, and call `navigator.credentials.get`. Send the assertion JSON to `/passkeys/login/finish`:

```json
{
  "challenge_token": "OPAQUE_CHALLENGE",
  "credential_response": {
    "id": "BASE64URL_CREDENTIAL_ID",
    "rawId": "BASE64URL_CREDENTIAL_ID",
    "type": "public-key",
    "response": {
      "clientDataJSON": "BASE64URL_CLIENT_DATA",
      "authenticatorData": "BASE64URL_AUTHENTICATOR_DATA",
      "signature": "BASE64URL_SIGNATURE",
      "userHandle": "BASE64URL_USER_HANDLE"
    }
  }
}
```

Login is discoverable/usernameless. The implementation resolves the stored credential, checks its user handle, verifies the assertion, and conditionally updates its signature counter. A non-increasing nonzero counter is rejected; counterless authenticators may remain at zero.

A completed response carries authentication credentials. If `data.challenges` is present, continue that flow instead; a verified passkey does not automatically bypass configured TOTP requirements. Cookie issuance follows `Security.AuthMode`.

## One-time Ceremonies

The opaque challenge contains encrypted WebAuthn session data. A hashed, purpose-bound Core token record prevents replay and distinguishes registration from login. Finish consumes the record before credential verification; a failed finish attempt requires a new begin request.

Registration and login require persistent shared Core and passkey storage across replicas. A passkey is not automatically an account-signup flow; users register credentials on an existing authenticated account.

## Managing Credentials

List returns summaries with `id`, `name`, optional `transports`, `created_at`, and optional `last_used_at`. It does not expose stored public-key material through this endpoint. Rename accepts `{"name":"New label"}`; rename/delete verify ownership. The login path updates the sign counter, but currently does not call the repository's `UpdateLastUsed`, so do not rely on `last_used_at` being populated.

See [Models](../api/models.md) for `PasskeyCredential` and `PasskeyRepository`, and [Security](../security.md) for the common authorization boundary.
