---
id: oauth
title: OAuth Module
sidebar_label: OAuth
sidebar_position: 6
---

# OAuth Module

The OAuth module adds social login and single sign-on capabilities to your application. Users can authenticate with their existing Google, GitHub, Microsoft, or Discord accounts. It supports the full OAuth 2.0 authorization code flow with optional PKCE (Proof Key for Code Exchange) for enhanced security, account linking to connect multiple providers to a single user, and both stateless JWT and server-side session auth modes.

## Capabilities

- **Multiple Providers** — Google, GitHub, Microsoft, and Discord out of the box. Each provider can be independently enabled/disabled without removing its configuration.
- **PKCE (Proof Key for Code Exchange)** — Optional per-provider PKCE support prevents authorization code interception attacks. Enabled by default. Particularly important for mobile and SPA clients.
- **Account Linking** — When enabled, if a user authenticates via OAuth with an email that already exists in your system, the OAuth identity is linked to the existing account rather than creating a duplicate.
- **Account Unlinking** — Users can disconnect an OAuth provider from their account via `DELETE /oauth/{provider}`, giving them control over linked identities.
- **Automatic Signup** — New users can be created automatically from OAuth profile data (email, name, avatar). Controlled via `AllowSignup`.
- **Provider Token Storage** — Optionally store the provider's access and refresh tokens (e.g., to call Google APIs on behalf of the user) via `StoreProviderTokens`.
- **Trust Email Verification** — When enabled, trusts the OAuth provider's email verification status and marks the user's email as verified in GoAuth.
- **Dual Auth Mode** — Works with both Stateless (JWT) and Session auth modules. Set `UseSessionAuth: true` to create server-side sessions instead of issuing JWTs.
- **Frontend Redirect or JSON** — Configurable `DefaultRedirectURL` for SPA flows (tokens in URL fragment) or JSON response for API-first clients.
- **Error Redirect** — Configurable `ErrorRedirectURL` for graceful error handling in the frontend.
- **Custom Storage** — Pass custom `CoreStorage`, `OAuthStorage`, and `SessionStorage` implementations.
- **Provider Discovery** — `GET /oauth/providers` lists all configured providers. `GET /oauth/linked` shows the authenticated user's linked providers.

## Supported Providers

Google, GitHub, Microsoft, Discord.

## Registration

```go
import (
    "github.com/bete7512/goauth/pkg/modules/oauth"
    "github.com/bete7512/goauth/pkg/config"
)

a.Use(oauth.New(&config.OAuthModuleConfig{
    Providers: map[string]*config.OAuthProviderConfig{
        "google": {
            ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
            ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
            PKCE:         true,
            Enabled:      true,
        },
        "github": {
            ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
            ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
            Enabled:      true,
        },
    },
    DefaultRedirectURL:     "http://localhost:3000/auth/callback",
    ErrorRedirectURL:       "http://localhost:3000/auth/error",
    AllowSignup:            true,
    AllowAccountLinking:    true,
    TrustEmailVerification: true,
    StoreProviderTokens:    false,
    UseSessionAuth:         false, // true to use sessions instead of JWT
}, nil))
```

The second argument to `oauth.New` is `*oauth.OAuthStorageOptions` -- pass `nil` to use the shared storage from `deps.Storage`.

**Important**: The OAuth module requires `APIURL` in your config for callback URL construction:

```go
a, _ := auth.New(&config.Config{
    APIURL: "https://api.yourapp.com",
    // ...
})
```

## Configuration

### OAuthModuleConfig

```go
type OAuthModuleConfig struct {
    Providers              map[string]*OAuthProviderConfig
    DefaultRedirectURL     string         // Frontend callback URL (tokens in URL fragment)
    ErrorRedirectURL       string         // Frontend error URL
    AllowSignup            bool           // Create new users via OAuth (default: true)
    AllowAccountLinking    bool           // Link OAuth to existing email accounts (default: true)
    TrustEmailVerification bool           // Trust provider's email verified status (default: true)
    StateTTL               time.Duration  // State token validity (default: 10min)
    StoreProviderTokens    bool           // Store provider access/refresh tokens (default: false)
    UseSessionAuth         bool           // Use sessions instead of JWT (default: false)
}
```

### OAuthProviderConfig

```go
type OAuthProviderConfig struct {
    ClientID     string
    ClientSecret string
    Scopes       []string  // Uses provider defaults if empty
    RedirectURL  string    // Override callback URL (auto-generated if empty)
    PKCE         bool      // Proof Key for Code Exchange (default: true)
    Enabled      bool      // Allows disabling without removing config
}
```

### Default scopes per provider

| Provider | Default Scopes |
|----------|---------------|
| Google | `openid`, `email`, `profile` |
| GitHub | `user:email`, `read:user` |
| Microsoft | `openid`, `email`, `profile`, `User.Read` |
| Discord | `identify`, `email` |

### Custom storage

Pass `*oauth.OAuthStorageOptions` as the second argument to `oauth.New` to override storage:

```go
oauth.New(oauthCfg, &oauth.OAuthStorageOptions{
    CoreStorage:    customCoreStorage,    // optional
    OAuthStorage:   customOAuthStorage,   // optional
    SessionStorage: customSessionStorage, // optional, only needed if UseSessionAuth=true
})
```

## Endpoints

| Method | Path | Middleware | Description |
|--------|------|------------|-------------|
| GET | `/oauth/{provider}` | -- | Start OAuth flow, redirects to provider |
| GET | `/oauth/{provider}/callback` | -- | Handle OAuth callback |
| DELETE | `/oauth/{provider}` | Auth | Unlink OAuth account |
| GET | `/oauth/providers` | -- | List configured providers |
| GET | `/oauth/linked` | Auth | List user's linked providers |

## Flow

1. Frontend redirects user to `GET /oauth/google`
2. GoAuth redirects to Google's consent screen (with PKCE challenge if enabled)
3. Google redirects back to `GET /oauth/google/callback`
4. GoAuth creates/links user account
5. If `DefaultRedirectURL` is set: redirects to `DefaultRedirectURL#access_token=xxx&refresh_token=xxx`
6. If `DefaultRedirectURL` is empty: returns JSON `AuthResponse`

### Error handling

If `ErrorRedirectURL` is set, auth failures redirect to `ErrorRedirectURL?error=xxx&error_description=xxx`. Otherwise a JSON error response is returned.

## Extensibility

### Custom Storage

Pass `*oauth.OAuthStorageOptions` as the second argument to `oauth.New()` to override any or all storage backends:

```go
a.Use(oauth.New(oauthCfg, &oauth.OAuthStorageOptions{
    CoreStorage:    myUserStore,      // implements types.CoreStorage
    OAuthStorage:   myOAuthStore,     // implements types.OAuthStorage
    SessionStorage: mySessionStore,   // implements types.SessionStorage (only if UseSessionAuth=true)
}))
```

When `nil`, all storage is obtained from the shared storage layer during initialization.

### Provider Token Access

When `StoreProviderTokens: true`, the OAuth module stores the provider's access token (and refresh token, if available) alongside the linked account record. This enables your application to make API calls to the OAuth provider on behalf of the user (e.g., accessing Google Calendar, GitHub repositories).

## Dependencies

- **Core** -- requires core module for user storage and authentication.

## Events

The OAuth module does not subscribe to or emit any events.
