---
id: index
title: GoAuth Documentation
seoTitle: "GoAuth: authentication library for Go (Golang)"
description: "GoAuth adds user accounts to a Go app as a library: sign-up, login, JWT, 2FA, OAuth2, passkeys, organizations, RBAC and an admin console in your own database."
keywords: ["golang authentication library", "go auth library", "go user authentication", "golang login system", "self-hosted auth go"]
sidebar_label: Overview
slug: /
---

# GoAuth Documentation

GoAuth adds user accounts to your Go app. It is a library, not a service: it runs inside the server you already have and stores users in the database you already use.

You do three things:

1. **Give it a database.** PostgreSQL, MySQL or SQLite. GoAuth creates and migrates its own tables.
2. **Mount its routes.** Your router gains working endpoints such as `POST /auth/signup`, `POST /auth/login` and `GET /auth/me`.
3. **Protect your own routes.** Wrap a handler in `a.RequireAuth(...)` and read the signed-in user from the request.

```text
               your Go server (one binary)
┌────────────────────────────────────────────────────────┐
│  your routes                  GoAuth's routes          │
│  GET  /api/orders             POST /auth/signup        │
│  POST /api/invoices           POST /auth/login         │
│        │                      GET  /auth/me    ...     │
│        └─ a.RequireAuth(handler)                       │
└────────────────────────────┬───────────────────────────┘
                             │
             your PostgreSQL, MySQL or SQLite
```

There is no extra service to deploy and no third party holding your users.

## Start here

| If you want to... | Read |
| --- | --- |
| Get a server running in five minutes | [Quick Start](quickstart.md) |
| Understand how the pieces fit before writing code | [Introduction](intro.md) |
| Add it to an existing project and database | [Installation](installation.md) |
| Copy a working setup for a feature | [Examples](showcase.md) |
| Compare it with Goth, Authboss, Ory Kratos, Keycloak or Auth0 | [Comparison](comparison.md) |
| See every endpoint, error code and model | [API Reference](api/endpoints.md) |
| Go live | [Production checklist](production.md) |

## What you can add

You start with sign-up and login. Everything else is a module you switch on with one line: social login, magic links, passkeys, SAML, two-factor, captcha, audit logging, organizations, teams, roles, an admin console, email and SMS, and acting as an OpenID Connect provider.

The [Introduction](intro.md#available-modules) lists every module, what it does and what it needs.

## The admin console

![The GoAuth admin console showing the users list, with search, bulk actions and CSV export](/img/console-users.png)

The [UI module](modules/ui.md) is a console for everything GoAuth manages: users, organizations, teams, invitations, roles and the audit log. It is embedded in the library and needs no build step.

## Where the project stands

GoAuth is in public beta.

- **These pages describe the `main` branch.** The SAML, Identity Provider, RBAC, Team and UI modules are not yet in the `v0.3.0-beta.1` release; [Installation](installation.md) shows how to get either.
- **A release may still contain breaking changes.** The [CHANGELOG](https://github.com/bete7512/goauth/blob/main/CHANGELOG.md) lists them first.
- **There has been no independent security audit.** Read the [Security guide](security.md) and the [Production checklist](production.md) before real users sign in.
