---
id: comparison
title: GoAuth vs Alternatives
sidebar_label: Comparison
seoTitle: "GoAuth vs Ory Kratos, Authboss, Goth and Keycloak"
description: How GoAuth compares with Goth, Authboss, Ory Kratos, Keycloak and hosted services such as Auth0, and when each one is the better choice for a Go app.
keywords: [goauth vs ory kratos, golang authentication library comparison, authboss alternative, goth alternative, keycloak alternative go, go authentication library, self-hosted auth0 alternative go]
---

# GoAuth vs Alternatives

There are several ways to add user accounts to a Go application. They fall into three groups:

- **Libraries** that you compile into your own server: GoAuth, Goth and Authboss.
- **Identity servers** that you deploy next to your application: Ory Kratos and Keycloak.
- **Hosted services** that run the accounts for you: Auth0, Clerk, Supabase Auth and others.

This page explains what each option is, what it does well, and when it is a better fit than GoAuth. GoAuth is newer than every project here. It is in public beta, several of its modules are experimental, it is maintained by one developer, and it has not had an independent security audit. Weigh that alongside the feature lists.

Details about other projects come from their own documentation and READMEs at the time of writing. Features change, so check their docs before you decide.

## Goth

[Goth](https://github.com/markbates/goth) (`markbates/goth`) is a Go library for signing in through third-party providers. It was inspired by Ruby's OmniAuth and lists more than 60 providers, including Google, GitHub, Facebook and a generic OpenID Connect provider. Its `gothic` helper package keeps the provider state in a `gorilla/sessions` cookie store. It is MIT licensed.

**What it does well.** Goth is small and focused. If all you need is "Sign in with X" and you already have your own user table and sessions, it gives you the provider handshake for a very long list of providers with little code.

**Where GoAuth differs.** Goth handles the OAuth exchange and returns the provider's user. It does not store users, issue your app's tokens or sessions, or handle passwords, email verification, 2FA or account recovery. GoAuth does all of that, and its [OAuth module](modules/oauth.md) covers fewer providers out of the box: Google, GitHub, Microsoft and Discord, plus providers you add in code with `oauth.NewWithProviders`.

**Pick Goth when** you only need social login, you want a provider GoAuth does not ship, or you already have the rest of your account system and do not want to replace it. Check the repository for its current maintenance status before you depend on it.

## Authboss

[Authboss](https://github.com/volatiletech/authboss) (`volatiletech/authboss`) is a modular authentication library for Go web applications. It is MIT licensed. Its modules include password authentication, registration, email confirmation, password recovery, account lock after failed attempts, login expiry, remember-me, OAuth2 sign-in, one-time passwords, and two-factor authentication through TOTP, SMS and backup codes.

**What it does well.** Authboss is the closest project to GoAuth in shape: a library with modules you enable as needed. It has been around much longer and leaves you in control of storage and rendering. You implement its storer interfaces for your own database, and a renderer for your own HTML or JSON responses.

**Where GoAuth differs.**

- **Storage.** Authboss ships no storage implementation; you write it. GoAuth ships a GORM-backed store for PostgreSQL, MySQL and SQLite with its own migrations, and you can still implement `types.Storage` yourself.
- **API shape.** Authboss renders through an interface you supply, with optional HTML views and a simple JSON renderer. GoAuth is API-first: JSON endpoints with an OpenAPI spec per module and a generated TypeScript client.
- **Scope.** GoAuth also includes passkeys, magic links, server-side sessions with a device list, organizations, nested teams, RBAC, an admin API and console, SAML sign-in and an OpenID Connect provider. Several of these are experimental. Passkeys, organizations and roles are not listed among Authboss's modules; check their docs.

**Pick Authboss when** you want a longer track record, you prefer to own the storage layer completely, or you are building a server-rendered app and want the library to fit around your own templates.

## Ory Kratos

[Ory Kratos](https://github.com/ory/kratos) is an open-source identity and user management server, written in Go and licensed under Apache-2.0. It is headless and API-first: it has no HTML rendering of its own, so you build the UI or use Ory's hosted pages. It covers self-service registration, login, account recovery, verification and settings, with passwords, social sign-in, passkeys, passwordless codes and TOTP. Identities are described by JSON Schema, and there are admin APIs for managing them. It also runs as a managed service on Ory Network.

Other parts of the Ory stack cover other jobs: [Ory Hydra](https://github.com/ory/hydra) is an OAuth 2.0 and OpenID Connect server, and [Ory Keto](https://github.com/ory/keto) is a Zanzibar-based permission server. According to the Kratos README, SAML, organization login and SCIM come with the Ory Enterprise License rather than the open-source edition.

**What it does well.** Kratos is mature, widely used and built for running at scale. Because it is a separate service, any number of applications in any language can share one identity system. Flexible identity schemas suit apps whose user profile does not fit a fixed table.

**Where GoAuth differs.** Kratos is a service you deploy, upgrade and monitor, with its own database. GoAuth runs inside your Go binary and writes to your database, so your code can join against the `users` table and calls into it are function calls. GoAuth also ships pieces that the Ory stack splits across separate services or the commercial edition: organizations, RBAC, an OpenID Connect provider, SAML sign-in and an admin console are modules in the same library, under the MIT license. In GoAuth those are experimental and newer.

**Pick Kratos when** several services in different languages need one login, you want a well-established project with commercial support available, or you prefer identity to run as its own service with its own scaling and release cycle.

## Keycloak

[Keycloak](https://www.keycloak.org/) is an open-source identity and access management server, licensed under Apache-2.0. It runs on Java (its getting-started guide requires OpenJDK) and is a Cloud Native Computing Foundation incubating project. It offers single sign-on and single sign-out, social login and identity brokering through OpenID Connect or SAML providers, LDAP and Active Directory federation, OpenID Connect, OAuth 2.0 and SAML 2.0 as a provider, passkeys, OTP, organizations, fine-grained authorization policies, an admin console and an account console for users.

**What it does well.** Keycloak is a full identity provider with a long history, a large community and extensive enterprise features. It suits organizations that need central single sign-on across many applications, directory integration, and configuration through a console rather than code.

**Where GoAuth differs.** Keycloak is a separate Java service and the source of truth for users; your application talks to it over standard protocols. GoAuth is a Go library inside your app. It is much smaller in scope: its SAML support is the service-provider side (signing users in from an identity provider such as Keycloak or Okta), it has no LDAP federation, and its OpenID Connect provider is experimental. In return, there is no second runtime to operate, and accounts live in the same database as your application data.

**Pick Keycloak when** you need central SSO for many applications, LDAP or Active Directory, a mature SAML or OIDC provider, or administrators who configure identity from a console. GoAuth can also sit behind Keycloak: its [SAML module](modules/saml.md) signs users in from a Keycloak realm.

## Hosted services: Auth0, Clerk, Supabase Auth

Hosted services run the account system for you. Details differ by vendor, so treat this as a group summary and check each vendor's docs and pricing.

- **[Auth0](https://auth0.com/docs)** (Okta) offers hosted Universal Login pages, passkeys, organizations, multi-factor authentication and enterprise connections.
- **[Clerk](https://clerk.com/docs)** offers prebuilt UI components, organizations, multi-factor authentication, and backend SDKs including one for Go.
- **[Supabase Auth](https://supabase.com/docs/guides/auth)** offers passwords, magic links, social providers, TOTP and phone MFA, and SAML single sign-on, with users stored in a Postgres schema that works with Postgres row-level security. Its server is [open source](https://github.com/supabase/auth), written in Go, MIT licensed and can be self-hosted, but it runs as its own service and requires PostgreSQL.

**What they do well.** Nothing to deploy or patch, polished sign-in pages, and a vendor responsible for uptime and security operations. Large vendors also publish compliance reports and offer support contracts and SLAs; check each vendor for the specific certifications you need.

**Where GoAuth differs.** With GoAuth, users live in your own database, there is no per-user price, and nothing leaves your infrastructure. The cost is that you operate it: upgrades, backups, key management and incident response are yours. GoAuth is API-first, so you also build your own sign-in pages, or use the plain pages in the [UI module](modules/ui.md).

**Pick a hosted service when** you want no authentication code or operations at all, need ready-made login UI, or need a vendor with an audit report, compliance certifications and an SLA.

## Summary

"Check their docs" means the feature was not confirmed in the project's own documentation for this page.

| | GoAuth | Goth | Authboss | Ory Kratos | Keycloak | Hosted (Auth0, Clerk, Supabase) |
| --- | --- | --- | --- | --- | --- | --- |
| **Kind** | Go library | Go library | Go library | Identity server (Go) | Identity server (Java) | Managed service |
| **Runs in your process** | Yes | Yes | Yes | No, separate service | No, separate service | No, vendor's cloud |
| **Storage** | Your database: PostgreSQL, MySQL, SQLite, or your own `types.Storage` | None; you store users | You implement its storer interfaces | Its own database (PostgreSQL, MySQL, CockroachDB, SQLite) | Its own database | Vendor-managed (Supabase: Postgres) |
| **Social login** | Google, GitHub, Microsoft, Discord, custom providers | 60+ providers | OAuth2 module | Yes | Yes | Yes |
| **Passkeys** | Yes (experimental) | No | Not listed; check their docs | Yes | Yes | Varies; check their docs |
| **2FA** | TOTP, backup codes | No | TOTP, SMS, backup codes | TOTP | OTP (TOTP/HOTP), recovery codes | Yes |
| **Organizations** | Yes, plus nested teams (experimental) | No | Not listed | Enterprise License / Ory Network | Yes | Auth0, Clerk: yes; others check their docs |
| **RBAC** | Yes (experimental) | No | Not listed | Separate server (Ory Keto) | Yes, plus policy-based authorization | Varies; check their docs |
| **OIDC provider** | Yes (experimental) | No | No | Separate server (Ory Hydra) | Yes | Varies; check their docs |
| **SAML** | Service provider (experimental) | No | Not listed | Enterprise License / Ory Network | Provider and broker | Auth0, Supabase: yes; others check their docs |
| **Admin UI** | Yes, embedded console | No | No | Headless; check their docs | Admin and account consoles | Vendor dashboard |
| **Maturity** | Public beta, one maintainer, no independent audit | Long-standing, widely used | Long-standing | Mature, commercial backing | Mature, CNCF incubating | Commercial vendors |

## When GoAuth is the wrong choice

- **You need a stable 1.0 API now.** GoAuth is in beta, and a release can still contain breaking changes.
- **You need an audit report, certifications or an SLA.** GoAuth has had no independent security audit and is maintained by one developer.
- **Your services are not all Go and need one central login.** An identity server such as Kratos or Keycloak, or a hosted service, fits better. GoAuth's OpenID Connect provider is experimental.
- **You need LDAP or Active Directory, or a mature SAML identity provider.** Keycloak covers these; GoAuth does not.
- **You want polished hosted login pages with no frontend work.** A hosted service gives you that. GoAuth is API-first.
- **You only need social login on top of an existing account system.** Goth is smaller and supports more providers.
- **Your database is not PostgreSQL, MySQL or SQLite** and you do not want to implement the storage interface.

## Next

- [Quick Start](quickstart.md): a running server and your first protected route.
- [Introduction](intro.md): how GoAuth works and every module it offers.
