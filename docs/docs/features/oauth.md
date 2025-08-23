---
id: oauth
title: OAuth Features
sidebar_label: OAuth
sidebar_position: 1
---

# OAuth Features

GoAuth provides comprehensive OAuth 2.0 support with multiple providers and advanced features.

## Supported Providers

### Social Login Providers

- **Google** - Google OAuth 2.0 with OpenID Connect
- **GitHub** - GitHub OAuth with user data access
- **Facebook** - Facebook Login with profile information
- **Apple** - Sign in with Apple (iOS/macOS apps)
- **Microsoft** - Microsoft Identity Platform
- **Discord** - Discord OAuth2 for gaming communities
- **LinkedIn** - LinkedIn OAuth 2.0 for professional networks
- **Twitter** - Twitter OAuth for social media integration

### Enterprise Providers

- **SAML 2.0** - Enterprise single sign-on
- **LDAP** - Directory service integration
- **Active Directory** - Windows domain authentication

## OAuth Flow Types

### 1. Authorization Code Flow

The most secure OAuth flow for web applications:

```go
// Initiate OAuth flow
func startOAuthFlow(c *gin.Context) {
    provider := c.Param("provider")
    state := generateSecureState()

    // Store state in session
    session.Set("oauth_state", state)

    // Redirect to OAuth provider
    authURL := auth.GetOAuthURL(provider, state)
    c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// Handle OAuth callback
func handleOAuthCallback(c *gin.Context) {
    code := c.Query("code")
    state := c.Query("state")

    // Verify state parameter
    if !verifyOAuthState(state) {
        c.JSON(400, gin.H{"error": "Invalid state"})
        return
    }

    // Exchange code for tokens
    result, err := auth.HandleOAuthCallback(c, provider, code)
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // Handle successful authentication
    handleOAuthSuccess(c, result)
}
```

### 2. Implicit Flow

For single-page applications (SPAs):

```go
// SPA OAuth flow
func spaOAuthFlow(c *gin.Context) {
    provider := c.Param("provider")
    redirectURI := c.Query("redirect_uri")

    // Generate OAuth URL for implicit flow
    authURL := auth.GetOAuthURL(provider, "", redirectURI, "token")
    c.JSON(200, gin.H{"auth_url": authURL})
}
```

### 3. PKCE Flow

Proof Key for Code Exchange for enhanced security:

```go
// PKCE OAuth flow
func pkceOAuthFlow(c *gin.Context) {
    provider := c.Param("provider")

    // Generate PKCE challenge
    codeVerifier := generateCodeVerifier()
    codeChallenge := generateCodeChallenge(codeVerifier)

    // Store code verifier
    session.Set("code_verifier", codeVerifier)

    // Get OAuth URL with PKCE
    authURL := auth.GetOAuthURLWithPKCE(provider, codeChallenge)
    c.Redirect(http.StatusTemporaryRedirect, authURL)
}
```

## Advanced Features

### 1. Account Linking

Link multiple OAuth accounts to a single user:

```go
// Link OAuth account
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

// Get linked accounts
func getLinkedAccounts(c *gin.Context) {
    user := auth.GetUser(c)

    accounts, err := auth.GetLinkedOAuthAccounts(c, user.ID)
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    c.JSON(200, gin.H{
        "linked_accounts": accounts,
    })
}
```

### 2. OAuth Scopes Management

Dynamic scope management based on user permissions:

```go
// Request additional scopes
func requestAdditionalScopes(c *gin.Context) {
    provider := c.Param("provider")
    scopes := c.QueryArray("scopes")

    // Validate requested scopes
    if !validateOAuthScopes(provider, scopes) {
        c.JSON(400, gin.H{"error": "Invalid scopes requested"})
        return
    }

    // Generate OAuth URL with additional scopes
    authURL := auth.GetOAuthURLWithScopes(provider, scopes)
    c.JSON(200, gin.H{"auth_url": authURL})
}

// Scope validation
func validateOAuthScopes(provider string, scopes []string) bool {
    allowedScopes := map[string][]string{
        "google": {"openid", "email", "profile", "calendar", "drive"},
        "github": {"user:email", "repo", "gist"},
        "facebook": {"email", "public_profile", "user_posts"},
    }

    providerScopes, exists := allowedScopes[provider]
    if !exists {
        return false
    }

    for _, scope := range scopes {
        if !contains(providerScopes, scope) {
            return false
        }
    }

    return true
}
```

### 3. OAuth Token Management

Advanced token handling and refresh:

```go
// Store OAuth tokens
type OAuthTokens struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    ExpiresAt    time.Time `json:"expires_at"`
    Scope        string    `json:"scope"`
}

// Refresh OAuth token
func refreshOAuthToken(c *gin.Context) {
    provider := c.Param("provider")

    var req struct {
        RefreshToken string `json:"refresh_token" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    tokens, err := auth.RefreshOAuthToken(c, provider, req.RefreshToken)
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    c.JSON(200, gin.H{
        "access_token": tokens.AccessToken,
        "refresh_token": tokens.RefreshToken,
        "expires_at": tokens.ExpiresAt,
    })
}
```

## Provider-Specific Features

### Google OAuth

```go
// Google-specific OAuth configuration
googleConfig := config.OAuthProvider{
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    RedirectURL:  "http://localhost:8080/auth/oauth/google/callback",
    Scopes: []string{
        "openid",
        "email",
        "profile",
        "https://www.googleapis.com/auth/calendar.readonly",
        "https://www.googleapis.com/auth/drive.readonly",
    },
    AdditionalParams: map[string]string{
        "access_type": "offline",
        "prompt": "consent",
    },
}
```

### GitHub OAuth

```go
// GitHub-specific OAuth configuration
githubConfig := config.OAuthProvider{
    ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
    ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
    RedirectURL:  "http://localhost:8080/auth/oauth/github/callback",
    Scopes: []string{
        "user:email",
        "read:user",
        "repo",
        "gist",
    },
}
```

### Facebook OAuth

```go
// Facebook-specific OAuth configuration
facebookConfig := config.OAuthProvider{
    ClientID:     os.Getenv("FACEBOOK_CLIENT_ID"),
    ClientSecret: os.Getenv("FACEBOOK_CLIENT_SECRET"),
    RedirectURL:  "http://localhost:8080/auth/oauth/facebook/callback",
    Scopes: []string{
        "email",
        "public_profile",
        "user_posts",
        "user_photos",
    },
}
```

## Security Features

### 1. State Parameter Validation

```go
// Generate secure state parameter
func generateSecureState() string {
    b := make([]byte, 32)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}

// Verify state parameter
func verifyOAuthState(state string) bool {
    storedState := session.Get("oauth_state")
    if storedState == nil {
        return false
    }

    // Clear state after verification
    session.Delete("oauth_state")

    return state == storedState.(string)
}
```

### 2. Redirect URI Validation

```go
// Validate redirect URIs
func validateRedirectURI(uri string) bool {
    allowedURIs := []string{
        "http://localhost:8080/auth/callback",
        "https://yourdomain.com/auth/callback",
        "https://app.yourdomain.com/auth/callback",
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

```go
// Validate OAuth scopes
func validateOAuthScopes(provider string, scopes []string) bool {
    minimalScopes := map[string][]string{
        "google":  {"openid", "email"},
        "github":  {"user:email"},
        "facebook": {"email"},
    }

    requiredScopes, exists := minimalScopes[provider]
    if !exists {
        return false
    }

    // Check if all required scopes are present
    for _, required := range requiredScopes {
        if !contains(scopes, required) {
            return false
        }
    }

    return true
}
```

## Error Handling

### Common OAuth Errors

```go
// Handle OAuth errors
func handleOAuthError(c *gin.Context, err error) {
    switch {
    case strings.Contains(err.Error(), "access_denied"):
        c.JSON(400, gin.H{
            "error": "User denied OAuth access",
            "code": "OAUTH_ACCESS_DENIED",
        })
    case strings.Contains(err.Error(), "invalid_grant"):
        c.JSON(400, gin.H{
            "error": "Invalid OAuth grant",
            "code": "OAUTH_INVALID_GRANT",
        })
    case strings.Contains(err.Error(), "server_error"):
        c.JSON(500, gin.H{
            "error": "OAuth provider error",
            "code": "OAUTH_SERVER_ERROR",
        })
    case strings.Contains(err.Error(), "invalid_client"):
        c.JSON(400, gin.H{
            "error": "Invalid OAuth client",
            "code": "OAUTH_INVALID_CLIENT",
        })
    default:
        c.JSON(400, gin.H{
            "error": "OAuth authentication failed",
            "code": "OAUTH_ERROR",
        })
    }
}
```

## Testing OAuth

### 1. Test OAuth Flow

```go
// Test OAuth initiation
func TestOAuthInitiation(t *testing.T) {
    // Setup test environment
    auth := setupTestAuth(t)

    // Test OAuth URL generation
    authURL := auth.GetOAuthURL("google", "test-state")

    assert.Contains(t, authURL, "accounts.google.com")
    assert.Contains(t, authURL, "test-state")
    assert.Contains(t, authURL, "response_type=code")
}

// Test OAuth callback handling
func TestOAuthCallback(t *testing.T) {
    // Setup test environment
    auth := setupTestAuth(t)

    // Mock OAuth callback
    code := "test-auth-code"
    state := "test-state"

    result, err := auth.HandleOAuthCallback(context.Background(), "google", code)

    assert.NoError(t, err)
    assert.NotNil(t, result)
    assert.NotEmpty(t, result.AccessToken)
}
```

### 2. Mock OAuth Provider

```go
// Mock OAuth provider for testing
type MockOAuthProvider struct {
    mockTokens map[string]OAuthTokens
}

func (m *MockOAuthProvider) ExchangeCode(code string) (*OAuthTokens, error) {
    if tokens, exists := m.mockTokens[code]; exists {
        return &tokens, nil
    }
    return nil, errors.New("invalid code")
}

func (m *MockOAuthProvider) GetUserInfo(tokens *OAuthTokens) (*models.User, error) {
    // Return mock user data
    return &models.User{
        ID:    "mock-user-id",
        Email: "mock@example.com",
        Name:  "Mock User",
    }, nil
}
```

## Next Steps

- [JWT Features](jwt.md) - Learn about JWT token management
- [Two-Factor Authentication](two-factor.md) - Add 2FA to your OAuth setup
- [Security Features](security.md) - Implement advanced security measures
- [Configuration](../configuration/auth.md) - Customize your OAuth configuration
