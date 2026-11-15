# GoAuth Modules

This document describes the modular architecture and how to register modules.

## Architecture

GoAuth follows a three-phase lifecycle:

```
auth.New(config) → auth.Use(module) → auth.Initialize(ctx)
```

Every module implements `config.Module` (8 methods): `Name`, `Init`, `Routes`, `Middlewares`, `Models`, `RegisterHooks`, `Dependencies`, `SwaggerSpec`.

Modules are registered with `auth.Use()` before `auth.Initialize()`. Order is enforced — `Use()` returns an error if called after `Initialize()`.

Reference implementation: `core/module.go`.

---

## Core Module

Auto-registered by `auth.New`. Provides user registration, profile management, password reset/change, email & phone verification, and availability checks.

Core does **not** handle login/logout/refresh — those are handled by the Session or Stateless module.

---

## Authentication Modules

Session and Stateless are **mutually exclusive**. Registering both returns an error from `Use()`. If neither is registered, Stateless is used as the default.

### Session Module

Server-side sessions with cookie strategies, session management (list/revoke), and sliding expiration.

```go
import "github.com/bete7512/goauth/internal/modules/session"

a.Use(session.New(&config.SessionModuleConfig{
    EnableSessionManagement: true,
    Strategy:                types.SessionStrategyCookieCache,
    CookieCacheTTL:          5 * time.Minute,
    SlidingExpiration:       true,
}, nil))
```

Provides: login, logout, refresh, session list, session get, session delete, session delete-all.

### Stateless Module

JWT access + refresh tokens with refresh token rotation.

```go
import "github.com/bete7512/goauth/internal/modules/stateless"

a.Use(stateless.New(&config.StatelessModuleConfig{
    RefreshTokenRotation: true,
}, nil))
```

Provides: login, logout, refresh.

---

## Notification Module

Email/SMS delivery with pluggable senders and customizable branding & templates. Hooks into core events (signup, password reset, login alerts) — no HTTP routes.

```go
import "github.com/bete7512/goauth/internal/modules/notification"

a.Use(notification.New(&notification.Config{
    EmailSender:              senders.NewSendGridEmailSender(&senders.SendGridConfig{
        APIKey:      "your-api-key",
        DefaultFrom: "noreply@yourapp.com",
    }),
    Branding: &templates.Branding{...},
    EnableWelcomeEmail:       true,
    EnablePasswordResetEmail: true,
    EnableLoginAlerts:        true,
}))
```

---

## Two-Factor Authentication

TOTP-based 2FA with backup codes. Provides setup, verify, disable, and status endpoints.

```go
import "github.com/bete7512/goauth/internal/modules/twofactor"

a.Use(twofactor.New(&twofactor.TwoFactorConfig{
    Issuer:           "MyApp",
    Required:         false,
    BackupCodesCount: 10,
    CodeLength:       8,
}))
```

---

## Captcha Protection

reCAPTCHA v3 or Cloudflare Turnstile. Applied to specific routes by name.

```go
import "github.com/bete7512/goauth/internal/modules/captcha"

a.Use(captcha.New(&captcha.CaptchaConfig{
    Provider:           "google",
    RecaptchaSiteKey:   "your-site-key",
    RecaptchaSecretKey: "your-secret-key",
    RecaptchaThreshold: 0.5,
    ApplyToRoutes:      []string{"core.signup", "core.login"},
}))
```

---

## CSRF Protection

Token-based CSRF protection for state-changing requests.

```go
import "github.com/bete7512/goauth/internal/modules/csrf"

a.Use(csrf.New(&csrf.CSRFConfig{
    TokenLength:      32,
    TokenExpiry:      3600,
    Secure:           true,
    HTTPOnly:         true,
    SameSite:         http.SameSiteStrictMode,
    ProtectedMethods: []string{"POST", "PUT", "DELETE", "PATCH"},
}))
```

---

## Admin Module

Admin-only endpoints for user CRUD (list, get, update, delete). Protected by admin middleware.

```go
import "github.com/bete7512/goauth/internal/modules/admin"

a.Use(admin.New(nil, nil))
```

---

## OAuth Module

Social login with providers: Google, GitHub, Facebook, Microsoft, Apple, Discord.

---

## SAML Module

SAML 2.0 service provider for enterprise IdPs (Keycloak, Okta, Entra ID, Shibboleth). Linked subjects are stored in the `accounts` table, so it depends on the OAuth module.

```go
import (
    "github.com/bete7512/goauth/pkg/modules/oauth"
    "github.com/bete7512/goauth/pkg/modules/saml"
)

a.Use(oauth.New(nil))
a.Use(saml.New(&config.SAMLModuleConfig{
    SPCertificate: spCertPEM,
    SPPrivateKey:  spKeyPEM,
    Providers: map[string]*config.SAMLProviderConfig{
        "keycloak": {MetadataURL: "http://localhost:8180/realms/demo/protocol/saml/descriptor", SignRequests: true},
    },
    AllowSignup: true,
    TrustEmail:  true,
}))
```

Provides: login (`/saml/{provider}/login`), ACS (`/saml/{provider}/acs`), SP metadata (`/saml/{provider}/metadata`), provider list.

---

## Identity Provider Module

OpenID Connect provider: other applications ("clients") sign users in with the host's accounts and receive an ID token. GoAuth has no login page, so the authorization endpoint hands the browser to the host's consent page. Depends on Core, and on the Admin module when `AdminAPI` is on.

```go
import "github.com/bete7512/goauth/pkg/modules/idp"

a.Use(idp.New(&config.IDPModuleConfig{
    SigningKey: config.IDPSigningKey{PrivateKeyPEM: signingKeyPEM}, // RSA, a key of its own
    ConsentURL: "https://app.example.com/oidc/consent",
    Clients: []config.IDPClientConfig{{
        ClientID:     "grafana",
        Secret:       os.Getenv("GRAFANA_OIDC_SECRET"),
        Name:         "Grafana",
        RedirectURIs: []string{"https://grafana.example.com/login/generic_oauth"},
    }},
}))
```

Provides: discovery (`/oidc/.well-known/openid-configuration`), keys (`/oidc/jwks`), authorize (`/oidc/authorize`), token (`/oidc/token`), UserInfo (`/oidc/userinfo`), consent (`/oidc/consent/{id}`, `/approve`, `/deny`), connected applications (`/oidc/grants`), and with `AdminAPI` client administration (`/admin/oidc/clients`).

Notes for contributors:
- The protocol endpoints return `*types.GoAuthError` whose `Code` is a `services.Code*` OAuth error; handlers render `{"error","error_description"}` through `writeOAuthError`. Consent, grant and admin endpoints use the normal envelope and `types.ErrIDP*`.
- ID tokens are signed by `security.TokenSigner.SignIDToken` with the module's own RSA key. `ResolveSettings` refuses a key that also verifies GoAuth's access tokens.
- Pending requests, codes, access tokens and refresh tokens are `tokens` rows (`idp_*` types) stored as digests, with no `UserID`: the stateless strategy deletes a user's token rows on logout, and logging out must not disconnect applications. Tokens are bound to the user's password (`credentialBinding`) instead.
- There is one grant per user and client; every token names it, so deleting it ends them all.
- Shared protocol rules (redirect URI matching, PKCE, scope parsing) live in `internal/oauthproto`.

---

## RBAC Module

Role-based access control for the host application's own routes and services: roles, who holds them, and the checks made against them. Depends on Core, and on the Organization module when `Organizations` is on.

```go
import "github.com/bete7512/goauth/pkg/modules/rbac"

authz := rbac.New(&rbac.Config{
    Organizations: true, // roles inside organizations; needs organization.New(...)
    Roles: []rbac.Role{
        {Key: "viewer", Grants: []string{"*:read"}},
    },
})
a.Use(authz)

mux.Handle("/invoices/", a.RequireAuth(authz.Resource("invoice")(invoices)))
mux.Handle("POST /invoices/{id}/approve", a.RequireAuth(authz.Require("invoice:approve")(approve)))
```

Provides: own permissions (`/me/permissions`), the permission catalog (`/rbac/permissions`), application-wide roles (`/rbac/roles`, `/rbac/roles/{roleKey}`), user roles (`/rbac/users/{userId}/roles`), assignments (`/rbac/assignments`), and with `Organizations` the same per organization (`/org/{orgId}/roles`, `/org/{orgId}/roles/{roleKey}`, `/org/{orgId}/members/{userId}/roles`, `/org/{orgId}/role-assignments`).

Notes for contributors:
- The permission grammar, grant matching and the "covers" check live in `access/`, which has no dependencies. `services/` resolves what a user holds; the module root holds the public API (`Require`, `Resource`, `Can`, `Check`, `For`) and its options.
- GoAuth's own permissions are in the reserved `goauth.` namespace, which a bare `*` never matches. Host permissions cannot use it.
- Roles defined in code are kept in memory; assignments name a role by key, so `rbac_role_assignments` has no foreign key to `rbac_roles`.
- `owner`, `admin`, `member` (organization scope) and `super_admin` are implied by membership and by `User.IsSuperAdmin`. They are never read from an assignment row. `organization_members.role` is only read.
- An organization assignment stores the membership row it was made for (`membership_id`) and counts only while that row exists, so rejoining an organization does not revive old roles. Event-driven cleanup is housekeeping only.
- Services take an `*Actor`. A nil actor is the host's own code and is trusted; with an actor, the permission is checked and every grant touched must be covered by the actor's own grants.
- Nothing is cached across requests. `services.WithMemo` remembers a holding for one request and every write resets it.
- A service or callback error is never turned into a denial: lookups that fail answer 500, and callbacks that panic refuse.

---

## Magic Link Module

Passwordless authentication via email.

---

## Audit Module

Logs security-relevant events for compliance and debugging.

---

## Complete Example

```go
package main

import (
    "context"
    "log"
    "net/http"
    "time"

    "github.com/bete7512/goauth/internal/modules/captcha"
    "github.com/bete7512/goauth/internal/modules/csrf"
    "github.com/bete7512/goauth/internal/modules/twofactor"
    "github.com/bete7512/goauth/pkg/adapters/stdhttp"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/types"
    "github.com/bete7512/goauth/storage"
)

func main() {
    store, err := storage.NewGormStorage(storage.GormConfig{
        Dialect: types.DialectTypeSqlite,
        DSN:     "auth.db",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close()

    a, err := auth.New(&config.Config{
        Storage:     store,
        AutoMigrate: true,
        Security: types.SecurityConfig{
            JwtSecretKey:  "your-secret-key-min-32-chars!!",
            EncryptionKey: "your-encryption-key-32-chars!!",
            Session: types.SessionConfig{
                AccessTokenTTL:  15 * time.Minute,
                RefreshTokenTTL: 7 * 24 * time.Hour,
            },
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    defer a.Close()

    // Stateless auth is the default — no need to register explicitly

    a.Use(twofactor.New(&twofactor.TwoFactorConfig{
        Issuer:           "MyApp",
        BackupCodesCount: 10,
    }))

    a.Use(captcha.New(&captcha.CaptchaConfig{
        Provider:           "cloudflare",
        TurnstileSiteKey:   "your-site-key",
        TurnstileSecretKey: "your-secret-key",
        ApplyToRoutes:      []string{"core.signup", "core.login"},
    }))

    a.Use(csrf.New(&csrf.CSRFConfig{
        TokenLength:      32,
        TokenExpiry:      3600,
        Secure:           false,
        HTTPOnly:         true,
        SameSite:         http.SameSiteStrictMode,
        ProtectedMethods: []string{"POST", "PUT", "DELETE", "PATCH"},
    }))

    if err := a.Initialize(context.Background()); err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    stdhttp.Register(mux, a)

    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

---

## Module Scaffolding

```bash
cd internal/modules
./new_module_with_route.sh mymodule      # Module with routes
./new_module_with_no_route.sh mymodule   # Middleware-only module
```

---

## Testing

```bash
make test           # All unit tests
make test-core      # Core module
make test-session   # Session module
make test-events    # Events
make test-verbose   # Verbose output
make mocks          # Regenerate mocks
make build          # Build
```

---

## Rate Limit Module

Registered automatically during `Initialize()` with `Config.RateLimit` (nil = default rules, in-memory store) unless `Config.RateLimit.Disabled` is set or the host registered it with `Use`. One global middleware (`ratelimit.limit`, priority 80) matches rules by the route name that `Auth.Routes()` stores in the request context under `types.RouteNameKey`.

```go
import "github.com/bete7512/goauth/pkg/modules/ratelimit"

a.Use(ratelimit.New(&config.RateLimitModuleConfig{
    Rules: ratelimit.DefaultRules(),
    Store: redisStore, // types.RateLimitStore; nil = memory
}))
```

Provides: no routes. Emits `types.EventRateLimitExceeded`; the audit module records `security.ratelimit.exceeded`. `Config.TrustedProxies` (root config) controls which peers' forwarded headers identify the client; the captcha middleware shares that helper.
