---
id: oauth-setup
title: OAuth Setup
sidebar_label: OAuth Setup
sidebar_position: 2
---

# OAuth Setup

Learn how to configure and implement OAuth authentication with GoAuth.

## Overview

OAuth 2.0 allows users to authenticate using their existing accounts from popular providers like Google, GitHub, Facebook, and more. GoAuth provides built-in support for multiple OAuth providers with a unified API.

## Supported Providers

GoAuth supports the following OAuth providers:

- **Google** - Google OAuth 2.0
- **GitHub** - GitHub OAuth
- **Facebook** - Facebook Login
- **Apple** - Sign in with Apple
- **Microsoft** - Microsoft Identity Platform
- **Discord** - Discord OAuth2
- **LinkedIn** - LinkedIn OAuth 2.0
- **Twitter** - Twitter OAuth 2.0

## Configuration

### 1. Provider Configuration

```go
cfg := &config.Config{
    OAuth: config.OAuthConfig{
        Providers: map[string]config.OAuthProvider{
            "google": {
                ClientID:     "your-google-client-id",
                ClientSecret: "your-google-client-secret",
                RedirectURL:  "http://localhost:8080/auth/oauth/google/callback",
                Scopes:      []string{"openid", "email", "profile"},
            },
            "github": {
                ClientID:     "your-github-client-id",
                ClientSecret: "your-github-client-secret",
                RedirectURL:  "http://localhost:8080/auth/oauth/github/callback",
                Scopes:      []string{"user:email"},
            },
            "facebook": {
                ClientID:     "your-facebook-client-id",
                ClientSecret: "your-facebook-client-secret",
                RedirectURL:  "http://localhost:8080/auth/oauth/facebook/callback",
                Scopes:      []string{"email", "public_profile"},
            },
        },
    },
}
```

### 2. Environment Variables

For production, use environment variables:

```bash
# Google OAuth
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret

# GitHub OAuth
GITHUB_CLIENT_ID=your-client-id
GITHUB_CLIENT_SECRET=your-client-secret

# Facebook OAuth
FACEBOOK_CLIENT_ID=your-client-id
FACEBOOK_CLIENT_SECRET=your-client-secret
```

## Implementation

### 1. OAuth Routes

GoAuth automatically sets up OAuth routes when configured:

```go
// Routes are automatically registered:
// GET  /auth/oauth/{provider}          - Initiate OAuth flow
// GET  /auth/oauth/{provider}/callback - OAuth callback
// POST /auth/oauth/{provider}/link     - Link OAuth account to existing user
```

### 2. Initiate OAuth Flow

```go
// Redirect user to OAuth provider
func initiateOAuth(c *gin.Context) {
    provider := c.Param("provider")

    // Generate OAuth state for security
    state := generateRandomState()

    // Store state in session/cache
    session.Set("oauth_state", state)

    // Redirect to OAuth provider
    authURL := auth.GetOAuthURL(provider, state)
    c.Redirect(http.StatusTemporaryRedirect, authURL)
}
```

### 3. OAuth Callback

```go
// Handle OAuth callback
func oauthCallback(c *gin.Context) {
    provider := c.Param("provider")
    code := c.Query("code")
    state := c.Query("state")

    // Verify state parameter
    if !verifyOAuthState(state) {
        c.JSON(400, gin.H{"error": "Invalid OAuth state"})
        return
    }

    // Exchange code for access token
    result, err := auth.HandleOAuthCallback(c, provider, code)
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // Handle successful authentication
    if result.IsNewUser {
        // New user - create account
        c.JSON(201, gin.H{
            "message": "Account created successfully",
            "user": result.User,
            "access_token": result.AccessToken,
        })
    } else {
        // Existing user - login
        c.JSON(200, gin.H{
            "message": "Login successful",
            "user": result.User,
            "access_token": result.AccessToken,
        })
    }
}
```

## Provider-Specific Setup

### Google OAuth

1. **Create Google Cloud Project**:

   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing one
   - Enable Google+ API

2. **Configure OAuth Consent Screen**:

   - Go to "APIs & Services" > "OAuth consent screen"
   - Set application type to "External"
   - Add required scopes: `openid`, `email`, `profile`

3. **Create OAuth Credentials**:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth 2.0 Client IDs"
   - Set application type to "Web application"
   - Add authorized redirect URIs

### GitHub OAuth

1. **Create GitHub OAuth App**:

   - Go to GitHub Settings > Developer settings > OAuth Apps
   - Click "New OAuth App"
   - Set application name and homepage URL
   - Set authorization callback URL

2. **Configure Scopes**:
   - `user:email` - Access user email addresses
   - `read:user` - Access user profile data

### Facebook OAuth

1. **Create Facebook App**:

   - Go to [Facebook Developers](https://developers.facebook.com/)
   - Create a new app
   - Add Facebook Login product

2. **Configure OAuth Settings**:
   - Set valid OAuth redirect URIs
   - Configure app domains
   - Set required permissions

## User Account Linking

### Link OAuth Account

```go
// Link OAuth account to existing user
func linkOAuthAccount(c *gin.Context) {
    user := auth.GetUser(c)
    provider := c.Param("provider")

    var req struct {
        Code  string `json:"code" binding:"required"`
        State string `json:"state" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    err := auth.LinkOAuthAccount(c, user.ID, provider, req.Code, req.State)
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    c.JSON(200, gin.H{
        "message": "OAuth account linked successfully",
    })
}
```

### Unlink OAuth Account

```go
// Unlink OAuth account
func unlinkOAuthAccount(c *gin.Context) {
    user := auth.GetUser(c)
    provider := c.Param("provider")

    err := auth.UnlinkOAuthAccount(c, user.ID, provider)
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    c.JSON(200, gin.H{
        "message": "OAuth account unlinked successfully",
    })
}
```

## Security Considerations

### 1. State Parameter

Always use and verify the `state` parameter to prevent CSRF attacks:

```go
func generateRandomState() string {
    b := make([]byte, 32)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}

func verifyOAuthState(state string) bool {
    storedState := session.Get("oauth_state")
    return state == storedState
}
```

### 2. Redirect URI Validation

Ensure redirect URIs are properly validated:

```go
// Validate redirect URI
func validateRedirectURI(uri string) bool {
    allowedURIs := []string{
        "http://localhost:8080/auth/callback",
        "https://yourdomain.com/auth/callback",
    }

    for _, allowed := range allowedURIs {
        if uri == allowed {
            return true
        }
    }
    return false
}
```

### 3. Scope Validation

Limit requested scopes to minimum required:

```go
// Minimal scopes for basic authentication
var minimalScopes = map[string][]string{
    "google":  {"openid", "email", "profile"},
    "github":  {"user:email"},
    "facebook": {"email", "public_profile"},
}
```

## Error Handling

Common OAuth errors and handling:

```go
// Handle OAuth errors
func handleOAuthError(c *gin.Context, err error) {
    switch {
    case strings.Contains(err.Error(), "access_denied"):
        c.JSON(400, gin.H{"error": "User denied OAuth access"})
    case strings.Contains(err.Error(), "invalid_grant"):
        c.JSON(400, gin.H{"error": "Invalid OAuth grant"})
    case strings.Contains(err.Error(), "server_error"):
        c.JSON(500, gin.H{"error": "OAuth provider error"})
    default:
        c.JSON(400, gin.H{"error": "OAuth authentication failed"})
    }
}
```

## Testing

### Test OAuth Flow

1. **Start OAuth Flow**:

   ```bash
   curl -X GET "http://localhost:8080/auth/oauth/google"
   ```

2. **Complete OAuth**:

   - User completes OAuth on provider site
   - Provider redirects to callback URL
   - Handle callback and create/login user

3. **Verify Authentication**:
   ```bash
   curl -X GET "http://localhost:8080/protected" \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
   ```

## Next Steps

- [Custom Storage](custom-storage.md) - Implement custom data storage
- [Security Features](../features/security.md) - Learn about advanced security features
- [Configuration](../configuration/auth.md) - Customize your OAuth setup
- [API Reference](../api/endpoints.md) - Explore the complete API
