---
id: compliance
title: Compliance & Security
sidebar_label: Compliance
---

# Compliance & Security

GoAuth is built to help you meet modern compliance requirements (GDPR, SOC2, HIPAA) by providing transparent security controls and auditability.

## Audit Logging

The [Audit Module](modules/audit.md) tracks every security-relevant event across your system. For compliance, you can configure:

- **Audit Trails**: Store audit logs in dedicated tables with configurable retention and automatic cleanup.
- **User Activity**: Allow users to download their own security logs for transparency.
- **Admin Oversight**: Track every change made by administrators to user accounts.

## Data Protection

- **Encryption at Rest**: Sensitive OAuth provider tokens are encrypted using AES-GCM before storage.
- **Password Security**: Uses bcrypt with configurable cost factor via `SecurityConfig`.
- **Session Control**: Revoke all active sessions instantly when a breach is suspected.

## Verification Flows

- **Email/Phone Verification**: Enforce verification before allowing access to sensitive data.
- **Two-Factor Authentication**: Native TOTP support for an additional layer of security.
- **Account Linking**: Securely link multiple identities to a single email with strict ownership verification.
