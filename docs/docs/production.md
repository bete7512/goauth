---
id: production
title: Production Checklist
sidebar_label: Production Checklist
---

# Production Checklist

Work through this list before real users sign in. Each item points to the page that explains it.

## Transport and cookies

- Serve every GoAuth route over HTTPS. Cookies are Secure by default; set `Security.Session.AllowInsecureCookies` only for local development over plain HTTP.
- Choose `Security.AuthMode` on purpose: `cookie` for browser apps, `bearer` for API clients, `both` (the default) only when you need both.
- Protect cookie-authenticated writes against CSRF with the [CSRF module](modules/csrf.md) or your framework, and configure CORS in your own middleware.

## Client addresses and abuse controls

- Set `Config.TrustedProxies` to your load balancers. Without it, every client shares the proxy's address in rate limits, captcha checks and audit logs.
- Rate limiting is on by default with a per-process store. With more than one replica, give it a shared `RateLimitStore`, or each replica enforces its own budget. See [Rate Limit](modules/ratelimit.md).
- Keep account lockout on (the default). Locked accounts look like wrong passwords unless you set `Security.Lockout.RevealLocked`.

## Secrets and keys

- Load `Security.JwtSecretKey` (at least 32 characters) and `Security.EncryptionKey` from a secret store, never from source control.
- Set `Security.JWTIssuer` and `Security.JWTAudience` to values unique to this deployment if other services share keys.
- Use RS256 or ES256 when other services verify tokens through the JWKS endpoint, and plan rotation with `Security.RetainedJWTKeys`. See [Signing-Key Rotation](security.md#signing-key-rotation).
- Set `Security.EncryptionKeyID` before the first encryption-key rotation. See [Encryption Rotation](security.md#encryption-rotation).

## Data and migrations

- Use PostgreSQL or MySQL; SQLite is for development and tests.
- Back up the database and check `MigrationStatus` before applying migrations, then apply them once per release with `Migration.Auto` or `ApplyMigrations`. See [Migrations](migrations.md).
- Single-use secrets are stored as digests, so a lost link cannot be read back; users request a new one.

## Modules and delivery

- Set `Config.FrontendConfig` so verification and password-reset links point at your frontend, and set the invitation callback URLs (`CallbackURL`, `InvitationCallbackURL`).
- Register the [notification module](modules/notification.md) with a real email or SMS sender, or deliver the `send.*` events yourself.
- OAuth: use stable connection IDs, pin Microsoft to your tenant UUID, keep `AllowAccountLinking` off unless you need it, and add the optional `xms_edov` claim for Microsoft sign-ups. See [OAuth](modules/oauth.md).
- Passkeys, Organization, Invitation and Admin are experimental: their API and schema may change during the beta.

## Operations

- Register the [audit module](modules/audit.md), or subscribe to `security.*` and `ratelimit.exceeded` events, and alert on bursts.
- Use `Config.Observer` for per-route metrics and `Config.Admission` for a concurrency budget shared across replicas.
- Call `Shutdown(ctx)` when the process stops so background workers drain.
- Run `govulncheck` on your application and keep GoAuth current.
- Report vulnerabilities as described in [SECURITY.md](https://github.com/bete7512/goauth/blob/main/SECURITY.md).
