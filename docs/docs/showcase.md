---
id: showcase
title: Examples
sidebar_label: Examples
description: GoAuth usage examples
---

# Examples

Start with the complete [Quick Start](quickstart.md) program. The fragments below run after `auth.New` and before `Initialize`; `a` is the auth instance and each fragment belongs in a function returning `error`.

## Session-Based Auth

Import `github.com/bete7512/goauth/pkg/modules/session` and `pkg/config`, `pkg/types`, and `time` from the quickstart:

```go
if err := a.Use(session.New(&config.SessionModuleConfig{
    Strategy: types.SessionStrategyCookieCache,
    CookieCacheTTL: 5 * time.Minute,
    SlidingExpiration: true,
})); err != nil {
    return err
}
```

Cookie caching applies only when cookie transport is enabled. Access validation still checks current user and session state. See [Session](modules/session.md).

## With Notifications

Import `pkg/modules/notification` and `pkg/modules/notification/senders` under the GoAuth module path, plus `os`:

```go
if err := a.Use(notification.New(&notification.Config{
    EmailSender: senders.NewSendGridEmailSender(&senders.SendGridConfig{
        APIKey: os.Getenv("SENDGRID_API_KEY"),
        DefaultFrom: "noreply@example.com",
    }),
    EnableWelcomeEmail: true,
    EnableLoginAlerts: true,
    EnablePasswordChangeAlert: true,
})); err != nil {
    return err
}
```

Password reset, magic-link, verification, and invitation delivery hooks are always registered. There is no `EnablePasswordResetEmail` flag.

## With Two-Factor Auth

Import `pkg/modules/twofactor`:

```go
if err := a.Use(twofactor.New(&config.TwoFactorConfig{
    Issuer: "MyApp",
    BackupCodesCount: 10,
    CodeLength: 8,
})); err != nil {
    return err
}
```

Handle the `challenges` response from any login method. `Required: true` requires existing enrollment; it does not enroll a user. See [Two-Factor](modules/twofactor.md).

## With Passkeys

Import `pkg/modules/passkeys`:

```go
if err := a.Use(passkeys.New(&config.PasskeysModuleConfig{
    RPID: "localhost",
    RPDisplayName: "MyApp",
    RPOrigins: []string{"http://localhost:3000"},
})); err != nil {
    return err
}
```

Use the browser's WebAuthn APIs and serialize binary fields as base64url. See the [Passkeys guide](modules/passkeys.md) for begin/finish payloads and production RP configuration.

## Teams and Administration

Import `pkg/modules/admin`, `audit`, `invitation`, and `organization`:

```go
for _, module := range []config.Component{
    admin.New(nil),
    audit.New(nil),
    invitation.New(nil),
    organization.New(nil),
} {
    if err := a.Use(module); err != nil {
        return err
    }
}
```

Admin supplies middleware required by Audit and Invitation. Organization roles scope membership in a workspace; they do not create independent identity realms. Persist all feature repositories in the same transaction-capable store.

## Demo App

The repository includes a [demo frontend](https://github.com/bete7512/go-auth/tree/main/demo). Match its API integration to the checkout you are running. For a complete backend baseline use the compiled quickstart, then add one module at a time.
