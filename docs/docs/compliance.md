---
id: compliance
title: Compliance & Security
sidebar_label: Compliance
---

# Compliance and Security Controls

GoAuth supplies authentication, persistence, and audit primitives that an application can use as part of its security controls. It does not certify a deployment or provide a complete GDPR, SOC 2, or HIPAA compliance program.

## Audit Logging

The [Audit module](modules/audit.md) subscribes to selected authentication, user, admin, and security events. Its coverage depends on enabled tracking flags, which events a flow actually emits, and successful delivery. It does not observe every security-relevant action automatically.

Configure per-action retention and review your own access/export policy for audit data. Application operations outside GoAuth require application instrumentation. For delivery guarantees, distinguish the in-memory backend from [acknowledged delivery and the transactional outbox](enterprise.md).

## Data Protection

Passwords use bcrypt and the configured byte-length policy. The default security manager encrypts explicitly protected fields with AES-GCM, including provider credentials and sealed continuation data. This does not encrypt the whole database; database and backup protection remain deployment concerns.

Session revocation and token-version changes are checked on subsequent online validation. Downstream services that only verify JWT signatures do not automatically observe those changes. See [Security and credentials](security.md).

## Verification and Authorization

Required email/phone verification and active-account status are checked before issuing and authorizing grants. OAuth email linking requires explicit opt-in and verified ownership on both sides. Two-factor enforcement occurs through the authentication completion flow; the current named route middleware is not a general step-up policy.

Organizations carry membership context inside the default identity realm. Enforce your product's resource permissions in addition to authentication. See [Organizations](modules/organization.md) and [Two-Factor](modules/twofactor.md) for current limits.
