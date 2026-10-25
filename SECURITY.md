# Security Policy

GoAuth is an authentication library, so we treat security reports as the highest-priority work in the project.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.3.x (beta) | Yes, latest release only |
| 0.2.x and earlier | No, retracted; upgrade |

During the beta, fixes ship in the next beta release. Upgrading from v0.2.x is described in the [upgrade guide](docs/docs/upgrade.md#upgrading-from-v02x).

## Reporting a vulnerability

Do not open a public issue or pull request for a vulnerability.

Report it privately through GitHub: **[Report a vulnerability](https://github.com/bete7512/goauth/security/advisories/new)** (Security tab, then "Report a vulnerability").

Please include:

- the GoAuth version or commit,
- the modules, storage backend and authentication strategy involved,
- steps or a test that reproduce the problem,
- the impact you expect.

## What to expect

- An acknowledgement within 5 business days.
- An assessment and a planned fix date after triage. We aim to ship fixes for critical and high-severity issues within 30 days.
- Coordinated disclosure through a GitHub security advisory once a fix is available, with credit to you unless you prefer otherwise.

## Scope

In scope: the library code in this repository (`pkg/`, `internal/`, `storage/`), the bundled modules and adapters, and the generated TypeScript client.

Out of scope: the demo deployment, the documentation site hosting, and vulnerabilities that exist only in a dependency. Report those upstream; CI tracks dependency advisories with govulncheck.

## Running GoAuth safely

The [security guide](docs/docs/security.md) describes the model. In production:

- serve over HTTPS and keep `Security.Session.AllowInsecureCookies` unset,
- set `Config.TrustedProxies` to your load balancers so rate limits and audit logs see real client addresses,
- give the rate limiter a shared store when you run more than one replica,
- add CSRF protection for cookie-authenticated writes,
- keep `JwtSecretKey` and `EncryptionKey` secret, and rotate them as the guide describes,
- apply migrations deliberately, as the [migrations guide](docs/docs/migrations.md) describes.
