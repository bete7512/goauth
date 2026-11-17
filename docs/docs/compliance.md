---
id: compliance
title: Compliance & Security
seoTitle: "GoAuth compliance: audit logs, GDPR and SOC 2 controls"
description: "What the GoAuth Go authentication library contributes to GDPR, SOC 2 or HIPAA work: password and secret handling, audit logs, and what stays your responsibility."
keywords: ["golang audit log", "go auth gdpr", "soc 2 authentication go", "compliance authentication library"]
sidebar_label: Compliance
---

# Compliance and Security Controls

GoAuth gives you building blocks for a compliance program: authentication, password and secret handling, and an audit trail. It does not certify your deployment and is not a complete GDPR, SOC 2 or HIPAA program.

## Audit Logging

The [Audit module](modules/audit.md) records selected authentication, user, admin and security events, with a retention period per action.

- Coverage depends on the tracking flags you enable, the events a flow emits, and successful delivery. It does not see every security-relevant action.
- Actions in your own application need your own instrumentation, and who may read or export audit data is your policy.
- For delivery guarantees, the default in-memory backend differs from [acknowledged delivery and the transactional outbox](enterprise.md).

## Data Protection

- Passwords are hashed with bcrypt, under a length policy measured in bytes.
- The default security manager encrypts explicitly protected fields with AES-GCM, including provider credentials and sealed continuation data. This is not encryption of the whole database; protecting the database and its backups is your deployment's job.
- A revoked session or a changed token version is caught the next time a request is validated. A service that only verifies JWT signatures does not see it. See [Security and credentials](security.md).

## Verification and Authorization

- Required email or phone verification and active-account status are checked before credentials are issued and on every authorized request.
- Linking an OAuth identity by email is opt-in and requires verified ownership on both sides.
- Two-factor is enforced at sign-in. Its route middleware is not a general "ask again before sensitive actions" policy.
- An organization gives a user a membership and a role. It is not a separate identity realm.
- Authentication tells you who the caller is. Enforce what they may do on your own resources too; the [RBAC module](modules/rbac.md) helps.

See [Organizations](modules/organization.md) and [Two-Factor](modules/twofactor.md) for their current limits.
