---
slug: enterprise-authentication-features
title: Enterprise-Ready Features in GoAuth
authors: [goauth-team]
tags: [enterprise, security, compliance, organizations, audit]
---

# Enterprise-Ready Features in GoAuth

GoAuth provides organization membership, administration, audit hooks, passkeys, and shared authentication policy as composable library features. This article is updated for the current checkout, including transactional storage, key rotation, and durable events.

<!-- truncate -->

## Organization membership

Users can belong to multiple organizations with the recognized roles `owner`, `admin`, and `member`. Unrecognized role strings do not receive privileges. Organizations are membership contexts inside the default identity realm, not separate user directories.

An organization becomes active through explicit selection. The grant carries `active_org_id` and `org_role`; validation rechecks the current organization and membership. Refresh retains that selection. Application-specific permissions remain the application's responsibility.

## Audit logging and retention

Register Admin alongside Audit so its admin routes can resolve their authorization middleware. Retention uses a map of action patterns to days:

```go
if err := a.Use(admin.New(nil)); err != nil {
    return err
}
if err := a.Use(audit.New(&audit.Config{
    TrackAuthEvents: true,
    TrackUserEvents: true,
    TrackAdminEvents: true,
    TrackSecurityEvents: true,
    RetentionDays: map[string]int{
        "auth.*": 90,
        "user.*": 90,
        "admin.*": 365,
        "security.*": -1,
    },
})); err != nil {
    return err
}
```

This fragment runs before initialization in a function returning `error`. The cleaner runs every 24 hours until its initialization context is cancelled. `SampleRate` is currently unused by the event handler. Audit subscriptions do not prove every operation emits the desired event; assess required coverage and add handlers where needed.

## Shared authentication policy

Password, OAuth, passkey, magic-link, and invitation proofs use shared completion. It checks current eligibility and runs interceptors before issuing credentials. TOTP requirements produce a stored, purpose-bound continuation; resumption consumes it atomically after the factor is verified.

Passkeys use RP ID and origin validation, one-use challenges, and atomic authenticator-counter updates. The current policy still applies configured 2FA to passkey login; it does not automatically treat a passkey as a 2FA bypass.

OAuth supports Google, GitHub, Microsoft, and Discord as built-in provider types. Named connections permit multiple configurations of a type. Google and Microsoft use verified OIDC ID tokens; Microsoft requires an explicit tenant. Browser-bound state and PKCE protect the authorization-code exchange. See [OAuth](/docs/modules/oauth) for the provider-map configuration.

## Events and transactional storage

The default in-memory worker pool is suitable when process-local delivery meets the application's needs. `DurableEvents` adds an outbox for supported operations, committing event records with their associated mutations. Delivery is at least once and acknowledged; deduplicate stable event IDs.

External broker integration uses the async backend interfaces. Durable local outbox dispatch does not automatically publish every event to an external broker. Review [Enterprise deployment](/docs/enterprise) for the exact contracts.

The bundled GORM adapter provides transaction-bound stores, conditional token rotation, migration coordination, and outbox leases. A custom `types.Storage` implementation must implement the corresponding capabilities. Combining independent stores in `StorageSet` alone cannot make cross-feature changes atomic.

## Deployment scope

GoAuth is a library with request observation and admission interfaces, not a hosted identity service. It does not ship SAML, LDAP, a general application RBAC engine, Redis storage, or broker infrastructure. [Compliance](/docs/compliance) describes the operational responsibilities around its security features.

Use [Examples](/docs/showcase), [Storage](/docs/storage), and [Upgrading](/docs/upgrade) when integrating the current API.
