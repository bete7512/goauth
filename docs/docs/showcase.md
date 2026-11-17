---
id: showcase
title: Examples
seoTitle: "GoAuth examples: Go authentication code you can run"
description: "Runnable GoAuth example projects for Go and short setups for sessions, email, two-factor, Google login, passkeys, organizations, roles and the admin console."
keywords: ["golang auth example", "go authentication sample code", "goauth examples", "go oauth example"]
sidebar_label: Examples
---

# Examples

Complete projects you can run, and short setups you can paste into your own server.

## Projects you can run

| Project | What it shows |
| --- | --- |
| [`examples/rbac`](https://github.com/bete7512/goauth/tree/main/examples/rbac) | "Acme Tracker": organizations, nested teams, every kind of permission check, and the admin console. Runs in memory, with demo users. |
| [`examples/idp`](https://github.com/bete7512/goauth/tree/main/examples/idp) | GoAuth as an OpenID Connect provider, with scripts that test it against Grafana and oauth2-proxy. |
| [`examples/main.go`](https://github.com/bete7512/goauth/blob/main/examples/main.go) | One server that uses most modules, with PostgreSQL and a NATS event backend. |
| [`demo/`](https://github.com/bete7512/goauth/tree/main/demo) | A Next.js frontend that talks to the API. |

The fastest way to see GoAuth working, admin console included:

```bash
git clone https://github.com/bete7512/goauth && cd goauth/examples
go run ./rbac
# open http://localhost:8080/admin/login and sign in as sam@tracker.test / Tracker-demo-1
```

## Setups to paste

Each fragment goes between `auth.New` and `a.Initialize` in the [Quick Start](quickstart.md) program. `a` is the auth instance, and the surrounding function returns `error`.

### Server-side sessions

For apps where users should see their devices and sign one out. Import `pkg/modules/session`, plus `time`.

```go
if err := a.Use(session.New(&config.SessionModuleConfig{
    Strategy: types.SessionStrategyCookieCache,
    CookieCacheTTL: 5 * time.Minute,
    SlidingExpiration: true,
})); err != nil {
    return err
}
```

This replaces the default JWT strategy. The cookie cache applies only when cookies are enabled, and every request still checks that the user and the session are current. See [Session](modules/session.md).

### Sending email

Without this module GoAuth sends nothing. Import `pkg/modules/notification` and `pkg/modules/notification/senders`, plus `os`.

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

The flags turn on optional emails. Password reset, verification, magic-link and invitation emails have no flag: they are always sent once the module is registered. SMTP, Resend and Twilio senders work the same way. See [Notification](modules/notification.md).

### Two-factor authentication

Authenticator-app codes with backup codes. Import `pkg/modules/twofactor`.

```go
if err := a.Use(twofactor.New(&config.TwoFactorConfig{
    Issuer: "MyApp",
    BackupCodesCount: 10,
    CodeLength: 8,
})); err != nil {
    return err
}
```

Any sign-in method can now answer with a `challenges` list instead of tokens. `Required: true` demands a factor from users who already enrolled; it does not enroll anyone. See [Two-Factor](modules/twofactor.md).

### Sign in with Google

Import `pkg/modules/oauth`, plus `os`.

```go
if err := a.Use(oauth.New(&config.OAuthModuleConfig{
    Providers: map[string]*config.OAuthProviderConfig{
        "google": {
            ClientID: os.Getenv("GOOGLE_CLIENT_ID"),
            ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
            Enabled: true,
        },
    },
    DefaultRedirectURL: "https://app.example.com/auth/callback",
    AllowSignup: true,
})); err != nil {
    return err
}
```

Two things are easy to miss: a provider without `Enabled: true` is skipped, and OAuth needs `APIURL` in the top-level config, because the callback you register with Google is `APIURL + BasePath + /oauth/google/callback`. GitHub, Microsoft and Discord work the same way. See [OAuth](modules/oauth.md).

### Passkeys

Sign-in with Touch ID, Face ID, Windows Hello or a security key. Import `pkg/modules/passkeys`.

```go
if err := a.Use(passkeys.New(&config.PasskeysModuleConfig{
    RPID: "localhost",
    RPDisplayName: "MyApp",
    RPOrigins: []string{"http://localhost:3000"},
})); err != nil {
    return err
}
```

`RPOrigins` is the address of the frontend that makes the browser's WebAuthn calls. See [Passkeys](modules/passkeys.md).

### Organizations and administration

Import `pkg/modules/admin`, `audit`, `invitation` and `organization`.

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

Audit and Invitation rely on Admin's middleware, so register it with them. With custom storage, keep all of these in one store that supports transactions.

### The admin console

A console for super admins at `/admin`. Import `pkg/modules/ui`.

```go
if err := a.Use(ui.New(&ui.Config{Path: "/admin"})); err != nil {
    return err
}
```

It has a page for every module you registered. See [UI](modules/ui.md).

### Roles and permissions

Import `pkg/modules/rbac`. Keep the value `rbac.New` returns, because its methods are the API.

```go
authz := rbac.New(&rbac.Config{
    Roles: []rbac.Role{
        {Key: "viewer", Grants: []string{"*:read"}},
        {Key: "accountant", Grants: []string{"invoice:*"}},
    },
})
if err := a.Use(authz); err != nil {
    return err
}
```

Then guard your own routes, after authentication:

```go
mux.Handle("POST /invoices/{id}/approve",
    a.RequireAuth(authz.Require("invoice:approve")(http.HandlerFunc(approve))))
```

See [RBAC](modules/rbac.md) for organization and team roles.
