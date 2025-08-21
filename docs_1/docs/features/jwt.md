---
id: jwt
title: JWT Features
sidebar_label: JWT
sidebar_position: 2
---

# JWT Features

GoAuth provides comprehensive JWT (JSON Web Token) support with advanced security features and flexible configuration.

## Overview

JWT tokens in GoAuth are used for stateless authentication, providing secure access to protected resources without maintaining server-side sessions.

## JWT Configuration

### Basic JWT Setup

```go
cfg := &config.Config{
    Security: config.SecurityConfig{
        JWTSecret:        "your-super-secret-jwt-key",
        JWTExpiration:    24 * time.Hour,
        RefreshExpiration: 7 * 24 * time.Hour,
        JWTIssuer:        "goauth",
        JWTAudience:      "your-app",
    },
}
```

### Advanced JWT Configuration

```go
cfg := &config.Config{
    Security: config.SecurityConfig{
        JWTSecret:        "your-super-secret-jwt-key",
        JWTExpiration:    24 * time.Hour,
        RefreshExpiration: 7 * 24 * time.Hour,
        JWTIssuer:        "goauth",
        JWTAudience:      "your-app",
        JWTAlgorithm:     "HS256",
        JWTKeyID:         "key-1",
        JWTClaims: map[string]interface{}{
            "version": "1.0",
            "app":     "myapp",
        },
    },
}
```

## JWT Token Types

### 1. Access Tokens

Short-lived tokens for API access:

```go
// Generate access token
func generateAccessToken(user *models.User) (string, error) {
    claims := jwt.MapClaims{
        "user_id": user.ID,
        "email":   user.Email,
        "role":    user.Role,
        "exp":     time.Now().Add(24 * time.Hour).Unix(),
        "iat":     time.Now().Unix(),
        "iss":     "goauth",
        "aud":     "your-app",
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(jwtSecret))
}

// Validate access token
func validateAccessToken(tokenString string) (*jwt.Token, error) {
    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(jwtSecret), nil
    })
}
```

### 2. Refresh Tokens

Long-lived tokens for token renewal:

```go
// Generate refresh token
func generateRefreshToken(user *models.User) (string, error) {
    claims := jwt.MapClaims{
        "user_id": user.ID,
        "type":    "refresh",
        "exp":     time.Now().Add(7 * 24 * time.Hour).Unix(),
        "iat":     time.Now().Unix(),
        "iss":     "goauth",
        "aud":     "your-app",
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(jwtSecret))
}

// Validate refresh token
func validateRefreshToken(tokenString string) (*jwt.Token, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(jwtSecret), nil
    })

    if err != nil {
        return nil, err
    }

    // Verify token type
    if claims, ok := token.Claims.(jwt.MapClaims); ok {
        if tokenType, exists := claims["type"]; !exists || tokenType != "refresh" {
            return nil, errors.New("invalid token type")
        }
    }

    return token, nil
}
```

## JWT Middleware

### Authentication Middleware

```go
// JWT authentication middleware
func JWTAuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Extract token from header
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(401, gin.H{"error": "Authorization header required"})
            c.Abort()
            return
        }

        // Parse Bearer token
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        if tokenString == authHeader {
            c.JSON(401, gin.H{"error": "Bearer token required"})
            c.Abort()
            return
        }

        // Validate token
        token, err := validateAccessToken(tokenString)
        if err != nil {
            c.JSON(401, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        // Extract claims
        if claims, ok := token.Claims.(jwt.MapClaims); ok {
            userID := claims["user_id"].(string)
            email := claims["email"].(string)
            role := claims["role"].(string)

            // Set user info in context
            c.Set("user_id", userID)
            c.Set("user_email", email)
            c.Set("user_role", role)

            c.Next()
        } else {
            c.JSON(401, gin.H{"error": "Invalid token claims"})
            c.Abort()
            return
        }
    }
}
```

### Role-Based Access Control

```go
// Role-based middleware
func RequireRole(roles ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        userRole, exists := c.Get("user_role")
        if !exists {
            c.JSON(401, gin.H{"error": "User role not found"})
            c.Abort()
            return
        }

        role := userRole.(string)
        for _, requiredRole := range roles {
            if role == requiredRole {
                c.Next()
                return
            }
        }

        c.JSON(403, gin.H{"error": "Insufficient permissions"})
        c.Abort()
    }
}

// Usage example
r.GET("/admin", JWTAuthMiddleware(), RequireRole("admin"), adminHandler)
r.GET("/user", JWTAuthMiddleware(), RequireRole("user", "admin"), userHandler)
```

## JWT Token Management

### Token Refresh

```go
// Refresh access token
func refreshAccessToken(c *gin.Context) {
    var req struct {
        RefreshToken string `json:"refresh_token" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // Validate refresh token
    token, err := validateRefreshToken(req.RefreshToken)
    if err != nil {
        c.JSON(401, gin.H{"error": "Invalid refresh token"})
        return
    }

    // Extract user ID from refresh token
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        c.JSON(401, gin.H{"error": "Invalid token claims"})
        return
    }

    userID := claims["user_id"].(string)

    // Get user from database
    user, err := getUserByID(userID)
    if err != nil {
        c.JSON(404, gin.H{"error": "User not found"})
        return
    }

    // Generate new access token
    accessToken, err := generateAccessToken(user)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to generate token"})
        return
    }

    c.JSON(200, gin.H{
        "access_token": accessToken,
        "expires_in":   24 * 60 * 60, // 24 hours in seconds
    })
}
```

### Token Revocation

```go
// Revoke refresh token
func revokeRefreshToken(c *gin.Context) {
    userID := c.GetString("user_id")

    var req struct {
        RefreshToken string `json:"refresh_token" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // Validate and extract token
    token, err := validateRefreshToken(req.RefreshToken)
    if err != nil {
        c.JSON(401, gin.H{"error": "Invalid refresh token"})
        return
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        c.JSON(401, gin.H{"error": "Invalid token claims"})
        return
    }

    tokenUserID := claims["user_id"].(string)

    // Ensure user can only revoke their own tokens
    if tokenUserID != userID {
        c.JSON(403, gin.H{"error": "Cannot revoke other user's tokens"})
        return
    }

    // Add token to blacklist or delete from database
    err = revokeToken(req.RefreshToken)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to revoke token"})
        return
    }

    c.JSON(200, gin.H{
        "message": "Token revoked successfully",
    })
}
```

## Advanced JWT Features

### Custom Claims

```go
// Custom JWT claims
type CustomClaims struct {
    jwt.StandardClaims
    UserID   string                 `json:"user_id"`
    Email    string                 `json:"email"`
    Role     string                 `json:"role"`
    Permissions []string            `json:"permissions"`
    Metadata map[string]interface{} `json:"metadata"`
}

// Generate token with custom claims
func generateTokenWithCustomClaims(user *models.User, permissions []string) (string, error) {
    claims := CustomClaims{
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
            IssuedAt:  time.Now().Unix(),
            Issuer:    "goauth",
            Audience:  "your-app",
        },
        UserID:      user.ID,
        Email:       user.Email,
        Role:        user.Role,
        Permissions: permissions,
        Metadata: map[string]interface{}{
            "last_login": user.LastLoginAt,
            "ip_address": user.LastIPAddress,
            "user_agent": user.LastUserAgent,
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(jwtSecret))
}
```

### Token Rotation

```go
// Implement token rotation for security
func rotateTokens(c *gin.Context) {
    userID := c.GetString("user_id")

    // Generate new refresh token
    user, err := getUserByID(userID)
    if err != nil {
        c.JSON(404, gin.H{"error": "User not found"})
        return
    }

    newRefreshToken, err := generateRefreshToken(user)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to generate refresh token"})
        return
    }

    newAccessToken, err := generateAccessToken(user)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to generate access token"})
        return
    }

    // Revoke old refresh token
    oldRefreshToken := c.GetHeader("X-Refresh-Token")
    if oldRefreshToken != "" {
        revokeToken(oldRefreshToken)
    }

    c.JSON(200, gin.H{
        "access_token":  newAccessToken,
        "refresh_token": newRefreshToken,
        "expires_in":    24 * 60 * 60,
    })
}
```

## JWT Security Features

### Token Blacklisting

```go
// Token blacklist implementation
type TokenBlacklist struct {
    cache map[string]time.Time
    mutex sync.RWMutex
}

func NewTokenBlacklist() *TokenBlacklist {
    return &TokenBlacklist{
        cache: make(map[string]time.Time),
    }
}

func (tb *TokenBlacklist) Add(token string, expiresAt time.Time) {
    tb.mutex.Lock()
    defer tb.mutex.Unlock()
    tb.cache[token] = expiresAt
}

func (tb *TokenBlacklist) IsBlacklisted(token string) bool {
    tb.mutex.RLock()
    defer tb.mutex.RUnlock()

    if expiresAt, exists := tb.cache[token]; exists {
        if time.Now().After(expiresAt) {
            // Remove expired tokens
            delete(tb.cache, token)
            return false
        }
        return true
    }

    return false
}

// Cleanup expired tokens periodically
func (tb *TokenBlacklist) Cleanup() {
    ticker := time.NewTicker(1 * time.Hour)
    go func() {
        for range ticker.C {
            tb.mutex.Lock()
            now := time.Now()
            for token, expiresAt := range tb.cache {
                if now.After(expiresAt) {
                    delete(tb.cache, token)
                }
            }
            tb.mutex.Unlock()
        }
    }()
}
```

### Rate Limiting for Token Endpoints

```go
// Rate limiting for token endpoints
func rateLimitTokenEndpoints() gin.HandlerFunc {
    limiter := rate.NewLimiter(rate.Every(1*time.Minute), 5) // 5 requests per minute

    return func(c *gin.Context) {
        if !limiter.Allow() {
            c.JSON(429, gin.H{"error": "Too many requests"})
            c.Abort()
            return
        }
        c.Next()
    }
}

// Apply rate limiting
r.POST("/auth/refresh", rateLimitTokenEndpoints(), refreshAccessToken)
r.POST("/auth/revoke", rateLimitTokenEndpoints(), revokeRefreshToken)
```

## JWT Testing

### Unit Tests

```go
func TestJWTGeneration(t *testing.T) {
    user := &models.User{
        ID:    "test-user",
        Email: "test@example.com",
        Role:  "user",
    }

    token, err := generateAccessToken(user)
    assert.NoError(t, err)
    assert.NotEmpty(t, token)

    // Validate token
    parsedToken, err := validateAccessToken(token)
    assert.NoError(t, err)

    claims, ok := parsedToken.Claims.(jwt.MapClaims)
    assert.True(t, ok)
    assert.Equal(t, user.ID, claims["user_id"])
    assert.Equal(t, user.Email, claims["email"])
}

func TestJWTExpiration(t *testing.T) {
    // Test expired token
    expiredToken := generateExpiredToken()

    _, err := validateAccessToken(expiredToken)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "token is expired")
}
```

### Integration Tests

```go
func TestJWTAuthenticationFlow(t *testing.T) {
    // Setup test server
    r := gin.New()
    r.POST("/auth/login", loginHandler)
    r.GET("/protected", JWTAuthMiddleware(), protectedHandler)

    // Test login
    loginReq := gin.H{
        "email":    "test@example.com",
        "password": "password123",
    }

    loginResp := performRequest(r, "POST", "/auth/login", loginReq)
    assert.Equal(t, 200, loginResp.Code)

    var loginResult map[string]interface{}
    json.Unmarshal(loginResp.Body.Bytes(), &loginResult)

    accessToken := loginResult["access_token"].(string)

    // Test protected endpoint
    headers := map[string]string{
        "Authorization": "Bearer " + accessToken,
    }

    protectedResp := performRequestWithHeaders(r, "GET", "/protected", nil, headers)
    assert.Equal(t, 200, protectedResp.Code)
}
```

## Best Practices

### 1. Token Storage

- **Access tokens**: Store in memory or short-lived cache
- **Refresh tokens**: Store securely in database with user association
- **Never store tokens in localStorage** (vulnerable to XSS)

### 2. Token Expiration

- **Access tokens**: 15 minutes to 1 hour
- **Refresh tokens**: 7 days to 30 days
- **Implement token rotation** for long-lived refresh tokens

### 3. Security Headers

```go
// Security headers middleware
func securityHeaders() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-XSS-Protection", "1; mode=block")
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        c.Next()
    }
}
```

### 4. Token Validation

- Always validate token signature
- Check token expiration
- Verify issuer and audience
- Implement token blacklisting for logout

## Next Steps

- [Two-Factor Authentication](two-factor.md) - Add 2FA to your JWT setup
- [Security Features](security.md) - Implement advanced security measures
- [Rate Limiting](rate-limiting.md) - Add rate limiting to your endpoints
- [Configuration](../configuration/auth.md) - Customize your JWT configuration
