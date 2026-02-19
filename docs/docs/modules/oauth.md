---
id: oauth
title: OAuth Module
sidebar_label: OAuth
sidebar_position: 6
---

# OAuth Module

Social login with multiple OAuth providers. Supports account linking, automatic signup, PKCE, and both stateless and session-based auth modes.

## Supported Providers

Google, GitHub, Facebook, Microsoft, Apple, Discord.

## Registration

```go
import "github.com/bete7512/goauth/internal/modules/oauth"

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
    UseSessionAuth:         false,  // true to use sessions instead of JWT
}, nil))
```

**Important**: The OAuth module requires `APIURL` in your config for callback URL construction:

```go
a, _ := auth.New(&config.Config{
    APIURL: "https://api.yourapp.com",
    // ...
})
```

## Configuration

```go
type OAuthModuleConfig struct {
    Providers              map[string]*OAuthProviderConfig
    DefaultRedirectURL     string  // Frontend callback URL (tokens in URL fragment)
    ErrorRedirectURL       string  // Frontend error URL
    AllowSignup            bool    // Create new users via OAuth (default: true)
    AllowAccountLinking    bool    // Link OAuth to existing email accounts (default: true)
    TrustEmailVerification bool    // Trust provider's email verified status (default: true)
    StateTTL               time.Duration  // State token validity (default: 10min)
    StoreProviderTokens    bool    // Store provider access/refresh tokens
    UseSessionAuth         bool    // Use sessions instead of JWT
}

type OAuthProviderConfig struct {
    ClientID     string
    ClientSecret string
    Scopes       []string  // Uses provider defaults if empty
    RedirectURL  string    // Override callback URL
    PKCE         bool      // Proof Key for Code Exchange (default: true)
    Enabled      bool
}
```

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/oauth/{provider}` | — | Start OAuth flow, redirects to provider |
| GET | `/oauth/{provider}/callback` | — | Handle OAuth callback |
| DELETE | `/oauth/{provider}` | ✓ | Unlink OAuth account |
| GET | `/oauth/providers` | — | List configured providers |
| GET | `/oauth/linked` | ✓ | List user's linked providers |

## Flow

1. Frontend redirects user to `GET /oauth/google`
2. GoAuth redirects to Google's consent screen
3. Google redirects back to `GET /oauth/google/callback`
4. GoAuth creates/links user, redirects to `DefaultRedirectURL#access_token=xxx&refresh_token=xxx`
