---
id: security
title: Security and Credentials
---

# Security and Credentials

GoAuth separates proof of identity, authentication completion, and access authorization. Password, OAuth, magic-link, passkey, and invitation flows submit verified evidence to a shared completer. It checks current account policy and factor requirements before issuing credentials.

## Credential Transport

`Security.AuthMode` accepts `types.AuthModeCookie`, `types.AuthModeBearer`, or `types.AuthModeBoth` (default). The `AuthModeCustom` constant still exists but config validation rejects it; custom transports can use [the in-process API](api/auth.md#in-process-authentication).

| Mode | Access input | Refresh input | Credential cookies issued |
| --- | --- | --- | --- |
| `cookie` | Access cookie | Refresh cookie | Yes |
| `bearer` | `Authorization: Bearer ...` | JSON `refresh_token` or Bearer header | No |
| `both` | Cookie or Bearer header | Cookie, JSON, or Bearer header | Yes |

If multiple enabled sources supply different credentials, validation rejects the request. Identical values are allowed. The default cookie names are `goauth_access_session` and `goauth_refresh_session`; the suffix is `Security.Session.Name`.

Issued credential cookies are HttpOnly and Secure by default; `Session.AllowInsecureCookies` drops the Secure attribute for local development over plain HTTP (Initialize logs a warning). They use `Session.SameSite` and `Session.Path`. `Name` defaults to `session`, `Path` to `/`, and SameSite to Lax. The current shared cookie helper does **not** set the configured `Session.Domain`; cookies remain host-only. `Session.MaxAge` does not override the per-credential TTL used by that helper.

Bearer-only mode does not issue credential cookies, but OAuth still needs its browser-binding cookie. Cookie-only mode controls credential extraction and cookies; successful JSON responses can still contain token fields. It is not a guarantee that credentials are omitted from response bodies.

Apply HTTPS cookie settings, CSRF protection for cookie-authenticated writes, and CORS in the host application. Cookie/bearer transport and Session/Stateless storage strategy are separate choices.

## Online Access Validation

The default security manager validates the configured algorithm/key, issuer, audience, required expiry, and issued-at rules. The access boundary also requires `type: access`, matching `sub`/`user_id`, a current token version, and an active user meeting required contact verification.

Session grants additionally require a live, owned, unexpired session. An `active_org_id` requires current membership with a recognized role and an active organization. These checks read storage; a valid signature alone does not authorize a request through GoAuth.

`types.PrincipalFromContext` exposes verified user, realm, session, organization, methods, authentication time, and expiry. Do not construct equivalent trust from unverified JWT payloads. The current realm is `default`; organization membership is not identity-realm isolation.

## JWT Algorithms and JWKS

HS256 is the default. RS256 and ES256 require signing-key material:

```go
security := types.SecurityConfig{
    JwtSecretKey: os.Getenv("JWT_SECRET_KEY"),
    EncryptionKey: os.Getenv("ENCRYPTION_KEY"),
    JWTAlgorithm: types.JWTAlgorithmRS256,
    JWTPrivateKeyFile: "/run/secrets/goauth-signing.pem",
    JWTKeyID: "signing-2026-10",
    JWTIssuer: "https://auth.example.com",
    JWTAudience: "my-api",
}
```

This config fragment uses `os` and `pkg/types`. A JWT secret of at least 32 bytes is still required for non-signing HMAC uses even with asymmetric signing. The encryption secret must be at least 16 bytes. Defaults for issuer and audience are both `goauth`; applications sharing key material should configure distinct values.

RSA signing keys must be at least 2048 bits. ES256 requires P-256. Inline PEM fields take precedence over file fields. The public key can be derived from the private key; an explicitly supplied public key must match. Invalid key configuration makes `auth.New` fail.

Core registers `GET {BasePath}/.well-known/jwks.json`. RS256/ES256 return the public key set directly, with a one-hour cache header. HS256 returns 404; no symmetric secret is published. A custom `SecurityManager` must implement the JWKS provider methods to expose keys.

External JWKS verification checks cryptographic validity, not current GoAuth account/session/membership state. Access and refresh credentials have distinct purposes even when signed by the same key.

## Signing-Key Rotation

Configure a new active signing key and retain previous verification keys for a bounded window:

```go
security.RetainedJWTKeys = []types.JWTVerificationKey{
    {
        ID: "previous-signing-key",
        Algorithm: types.JWTAlgorithmRS256,
        PublicKeyPEM: previousPublicKey,
        NotAfter: retirementTime,
    },
}
```

Every retained key needs a nonempty ID distinct from the active ID, a supported algorithm, and a nonzero retirement time. HS256 retained keys use `Secret`; asymmetric keys use `PublicKeyPEM`. Retained keys verify only; new credentials use the active key. Unknown, retired, or algorithm-mismatched key IDs are rejected. The public key set includes unexpired retained asymmetric keys.

Rotation is configured at construction, not through a live key-management API. Plan the overlap around credential lifetime and downstream JWKS caches. For HMAC rotation, issue credentials with a stable nonempty `JWTKeyID` before switching keys; legacy tokens without that ID cannot select a retained key by name.

## Encryption Rotation

The default manager encrypts using AES-GCM with a SHA-256-derived key. New ciphertext carries an encryption key ID. Set `EncryptionKeyID` for the active secret and keep previous ID-to-secret entries in `DecryptionKeys` while stored encrypted values or continuations still need them.

This encrypts fields explicitly passed through the manager, such as stored provider credentials and sealed ceremony data. It is not transparent encryption of every database column. There is no automatic re-encryption job; manage migration and key retirement in your application.

## Passwords and Lockout

Password policy uses **bytes**, matching bcrypt's 72-byte input limit. Defaults are minimum 8 and maximum 72; configured maximums above 72 are capped. Inputs are not trimmed, normalized, or truncated by the policy. Optional uppercase, lowercase, number, and special-character requirements apply to password writes. Bcrypt cost uses `HashSaltLength` (default 10).

A locked account receives the same `INVALID_CREDENTIALS` answer as a wrong password, so lockout cannot be used to confirm that an account exists or to learn that a deliberate lockout worked; set `Lockout.RevealLocked: true` to answer `ACCOUNT_LOCKED` (423) instead. The password is still checked while an account is locked, and a login for an unknown identifier costs one password hash, so response timing does not reveal account or lock state. Enable lockout explicitly with `Lockout.Enabled: true`. Defaults for its numeric fields are five attempts and a 15-minute duration; config validation does not turn a false `Enabled` value into true. Use the centralized password flow rather than bypassing it with direct repository writes.

## Authentication Challenges

Challenges block issuance in login, refresh, and resume phases. A pending token is purpose-bound and persisted; it cannot authorize a protected endpoint. The current 2FA HTTP flow requires `temp_token` and `code`, limits attempts, and atomically consumes the continuation before final issuance. See [Two-Factor](modules/twofactor.md) for enforcement and enrollment limits.

Grant context preserves original authentication time and verified methods through refresh. Extensions cannot replace reserved identity, purpose, lifetime, session, or assurance claims. JWT signing rejects a claims payload larger than 4096 bytes.

## Operational Controls

Built-in routes limit concurrent requests (default 128) and request bodies (default 1 MiB). Optional `AdmissionController` and `OperationObserver` integrate shared capacity and telemetry. These do not replace endpoint-specific abuse prevention or the application's authorization policy.

[Audit logging](modules/audit.md) records configured events. Review actual emitted events and delivery guarantees before depending on an audit trail; see [Events and deployment](enterprise.md).
