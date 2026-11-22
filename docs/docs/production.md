---
id: production
title: Production Checklist
seoTitle: "Go authentication production checklist"
description: "Checklist before real users sign in to your Go app with GoAuth: HTTPS and secure cookies, proxies and rate limits, secrets and keys, database, email and operations."
keywords: ["golang auth production", "go authentication checklist", "deploy goauth", "go auth best practices"]
sidebar_label: Production Checklist
---

# Production Checklist

Work through this list before real users sign in. Each item links to the page that explains it.

Short on time? Do these five first: HTTPS, `Config.TrustedProxies`, secrets from a secret store, PostgreSQL or MySQL, and a real email sender.

## Transport and cookies

- **Serve every GoAuth route over HTTPS.** Cookies are Secure by default. Set `Security.Session.AllowInsecureCookies` only for local development over plain HTTP.
- **Choose `Security.AuthMode` on purpose:** `cookie` for browser apps, `bearer` for API clients, and `both` (the default) only when you need both.
- **Protect cookie-authenticated writes against CSRF** with the [CSRF module](modules/csrf.md) or your framework, and configure CORS in your own middleware.

## Client addresses and abuse controls

- **Set `Config.TrustedProxies` to your load balancers.** Without it, every client appears to come from the proxy's address in rate limits, captcha checks and audit logs.
- **Give the rate limiter a shared store when you run more than one replica.** Its default store lives in one process, so otherwise each replica enforces its own budget. See [Rate Limit](modules/ratelimit.md).
- **Keep account lockout on,** which is the default. A locked account looks like a wrong password unless you set `Security.Lockout.RevealLocked`.

## Secrets and keys

- **Load `Security.JwtSecretKey` (at least 32 characters) and `Security.EncryptionKey` from a secret store,** never from source control. Keep them stable across deploys.
- **Set `Security.JWTIssuer` and `Security.JWTAudience`** to values unique to this deployment if other services share keys.
- **Use RS256 or ES256 when other services verify tokens** through the JWKS endpoint, and plan rotation with `Security.RetainedJWTKeys`. See [Signing-Key Rotation](security.md#signing-key-rotation).
- **Set `Security.EncryptionKeyID` before the first encryption-key rotation.** See [Encryption Rotation](security.md#encryption-rotation).

## Data and migrations

- **Use PostgreSQL or MySQL.** SQLite is for development and tests.
- **Back up the database and check `MigrationStatus` before applying migrations.** Then apply them once per release with `Migration.Auto` or `ApplyMigrations`. See [Migrations](migrations.md).
- **Expect lost links to be re-sent, not recovered.** Single-use secrets are stored as digests, so the user asks for a new one.

## Modules and delivery

- **Set `Config.FrontendConfig`** so verification and password-reset links point at your frontend, and set the invitation callback URLs (`CallbackURL`, `InvitationCallbackURL`).
- **Register the [Notification module](modules/notification.md) with a real email or SMS sender,** or deliver the `send.*` events yourself. If you do neither, nobody receives a reset or verification message.
- **OAuth:** use stable connection IDs, pin Microsoft to your tenant UUID, keep `AllowAccountLinking` off unless you need it, and add the optional `xms_edov` claim for Microsoft sign-ups. See [OAuth](modules/oauth.md).
- **Know which modules are experimental:** Passkeys, SAML, Identity Provider, Organization, Team, RBAC, Invitation and Admin. Their API and schema may change before 1.0.

## Operations

- **Watch for attacks.** Register the [Audit module](modules/audit.md), or subscribe to `security.*` and `ratelimit.exceeded` events, and alert on bursts.
- **Measure and limit.** Use `Config.Observer` for per-route metrics and `Config.Admission` for a concurrency budget shared across replicas.
- **Shut down cleanly.** Stop the HTTP server, then call `Shutdown(ctx)` so background workers drain.
- **Build with the latest Go patch release.** GoAuth requires Go 1.26, but early 1.26 patches have standard-library advisories that `govulncheck` reports.
- **Run `govulncheck` on your application** and keep GoAuth current.
- **Report vulnerabilities** as described in [SECURITY.md](https://github.com/bete7512/goauth/blob/main/SECURITY.md).
