---
id: oauth
title: OAuth Module
sidebar_label: OAuth
sidebar_position: 6
---

# OAuth Module

OAuth provides authorization-code sign-in through Google, GitHub, Microsoft, and Discord, with named connections and a public interface for custom trusted providers. Successful identity verification enters the same completion service as password, passkey, and magic-link authentication.

## Registration

```go
if err := a.Use(oauth.New(&config.OAuthModuleConfig{
    Providers: map[string]*config.OAuthProviderConfig{
        "google": {
            ClientID: os.Getenv("GOOGLE_CLIENT_ID"),
            ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
            Enabled: true,
            PKCE: true,
        },
        "work": {
            Type: "microsoft",
            MicrosoftTenantID: os.Getenv("MICROSOFT_TENANT_ID"),
            ClientID: os.Getenv("MICROSOFT_CLIENT_ID"),
            ClientSecret: os.Getenv("MICROSOFT_CLIENT_SECRET"),
            Enabled: true,
            PKCE: true,
        },
    },
    AllowSignup: true,
    AllowAccountLinking: false,
    TrustEmailVerification: true,
    DefaultRedirectURL: "http://localhost:3000/auth/callback",
})); err != nil {
    return err
}
```

Import `pkg/modules/oauth`, `pkg/config`, and `os`. Set `config.Config.APIURL`, for example `http://localhost:8080`. With `BasePath: "/api/v1"`, register `http://localhost:8080/api/v1/oauth/google/callback` with Google and `/api/v1/oauth/work/callback` with the named Microsoft connection.

The constructor takes a single config argument. Boolean values in a supplied config are explicit: omitting `AllowSignup` or `TrustEmailVerification` leaves them false. `oauth.New(nil)` defaults those two to true and linking to false, but has no configured providers.

## Named Connections and Providers

The map key is the **connection ID**, used in URLs and stored account identity. IDs match `[A-Za-z0-9_-]{1,64}`. `Type` selects the built-in adapter; if empty it defaults to the map key. This permits multiple connections to the same provider type.

Microsoft requires `MicrosoftTenantID` to be an explicit tenant UUID. Google and Microsoft verify ID-token signature, exact issuer, audience, lifetime, subject, and the nonce persisted in the login continuation. The built-in implementation does not provide generic OIDC discovery from arbitrary issuer input.

| Provider type | Default scopes |
| --- | --- |
| `google` | `openid`, `email`, `profile` |
| `github` | `user:email`, `read:user` |
| `microsoft` | `openid`, `email`, `profile`, `User.Read` |
| `discord` | `identify`, `email` |

The service generates an S256 PKCE challenge/verifier for the flow and supplies it to the provider. The current built-in request construction sends those supplied values; do not use `PKCE: false` as a guarantee that PKCE is disabled.

## Configuration

| Field | Effective behavior |
| --- | --- |
| `Providers` | Named built-in connections; nil or disabled entries are skipped |
| `DefaultRedirectURL` | Frontend destination after complete authentication; empty returns JSON |
| `ErrorRedirectURL` | Error destination with `error`/`error_description` query parameters |
| `AllowSignup` | Permit a new user to be created from an external identity |
| `AllowAccountLinking` | Explicit opt-in for matching-email linking; additional verification checks apply |
| `TrustEmailVerification` | Trust a provider's verified-email result |
| `StateTTL` | Stored state lifetime, default 10 minutes |
| `StoreProviderTokens` | Encrypt provider access/refresh tokens before persistence |
| `UseSessionAuth` | Legacy setting; the initialized runtime's selected Session/Stateless strategy controls final grants |
| `CustomCoreStorage`, `CustomOAuthStorage`, `CustomSessionStorage` | Currently rejected during OAuth initialization; use a single aggregate transactional storage adapter |

A provider config includes `Type`, `MicrosoftTenantID`, `ClientID`, `ClientSecret`, `Scopes`, `RedirectURL`, `PKCE`, and `Enabled`. Set `Enabled: true` explicitly. The runtime service constructs the callback from `APIURL + BasePath + "/oauth/" + connection + "/callback"` and supplies it to the provider; a per-provider `RedirectURL` is not a reliable override of that runtime callback.

## Endpoints

All paths are relative to `BasePath`.

| Method | Path | Access auth | Description |
| --- | --- | --- | --- |
| GET | `/oauth/{provider}` | No | Start a named connection's flow |
| GET | `/oauth/{provider}/callback` | No | Complete the browser-bound callback |
| GET | `/oauth/providers` | No | List enabled connection IDs |
| GET | `/oauth/linked` | Required | List the user's linked connections |
| DELETE | `/oauth/{provider}` | Required | Unlink an owned connection |

## Flow

1. The browser visits the start endpoint. The service stores state with connection ID, nonce, verifier, and requested frontend destination.
2. The handler sets an HttpOnly, SameSite=Lax `goauth_oauth_{connection}` binding cookie and redirects to the provider.
3. The callback must present both matching state and the browser cookie. The binding cookie currently lasts 600 seconds independently of a longer configured `StateTTL`.
4. The service atomically consumes state, exchanges the code, and verifies the provider identity. OIDC requires the expected nonce; failed OIDC validation does not fall back to unverified userinfo.
5. Account lookup/link/create runs with transaction-bound Core and OAuth stores.
6. The common completer checks current eligibility and additional-factor policy before issuing the selected grant.

Continue the flow in the same browser cookie context. A callback copied into a separate HTTP client without its binding cookie is rejected.

If more factors are required, the callback returns JSON `data.challenges`, even when a frontend redirect is configured. After complete authentication, cookie-only mode redirects without token fragments. Bearer/both mode may put credentials in the fragment. No redirect returns the normal JSON auth response. A requested `redirect_uri` must match the scheme and host of configured frontend/error/default destinations.

## Account Linking and Identity

A matching email is insufficient on its own. Linking an existing account requires `AllowAccountLinking`, `TrustEmailVerification`, a verified provider email, and a locally verified email. Linking is disabled by default for a nil module config.

Stored identity includes the connection ID, provider subject, issuer when supplied, and realm `default`. A changed issuer or mismatched realm is rejected. Organizations are membership contexts inside that realm, not independent identity namespaces.

## Custom Providers

Use `oauth.NewWithProviders(cfg, map[string]oauth.Provider)` to install trusted in-process providers before initialization. It returns `(config.Module, error)`. The public package also exports `AuthCodeURLOptions`, `ExchangeOptions`, `TokenResponse`, and `UserInfo` aliases for implementations.

A custom provider must verify its protocol before returning identity information. Provider registration is frozen after initialization. There is no runtime HTTP endpoint for accepting arbitrary provider implementations or issuer URLs.

## Storage and Events

OAuth identity mutation requires `types.TransactionalStorage` binding Core and OAuth stores to the same transaction. The shared strategy also needs its credential stores. See [Custom storage](../storage.md).

`StoreProviderTokens` encrypts stored provider credentials and excludes them from model JSON. Applications needing provider API access must retrieve and decrypt them through their own trusted integration.

The current service emits `EventAfterOAuthLogin`, `EventOAuthLinkAdded`, and `EventOAuthLinkRemoved` in their corresponding completed paths. The existence of other OAuth event constants does not mean every path emits them.
