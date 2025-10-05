---
id: gin
title: Gin Framework Integration
sidebar_label: Gin
sidebar_position: 1
---

# Gin Framework Integration

GoAuth provides seamless integration with the Gin web framework, offering a clean and efficient way to implement authentication in your Gin applications.

## Overview

Gin is a high-performance HTTP web framework written in Go. GoAuth's Gin integration provides:

- Middleware for authentication
- Route protection
- User context management
- Error handling
- Performance optimization

## Installation

### 1. Install Dependencies

```bash
go get github.com/gin-gonic/gin
go get github.com/bete7512/goauth
```

### 2. Import Packages

```go
import (
    "context"
    "net/http"
    "github.com/gin-gonic/gin"
    "github.com/bete7512/goauth/internal/storage"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
)
```

## Basic Setup

### 1. Initialize GoAuth with Gin

```go
package main

func main() {
    store, _ := storage.NewStorage(config.StorageConfig{Driver: "gorm", Dialect: "sqlite", DSN: "auth.db", AutoMigrate: true})
    a, _ := auth.New(&config.Config{Storage: store, AutoMigrate: true, Security: config.SecurityConfig{JwtSecretKey: "...", EncryptionKey: "..."}})
    _ = a.Initialize(context.Background())

    r := gin.Default()
    for _, rt := range a.Routes() {
        switch rt.Method {
        case http.MethodGet:
            r.GET(rt.Path, gin.WrapF(rt.Handler))
        case http.MethodPost:
            r.POST(rt.Path, gin.WrapF(rt.Handler))
        case http.MethodPut:
            r.PUT(rt.Path, gin.WrapF(rt.Handler))
        case http.MethodDelete:
            r.DELETE(rt.Path, gin.WrapF(rt.Handler))
        case http.MethodPatch:
            r.PATCH(rt.Path, gin.WrapF(rt.Handler))
        case http.MethodOptions:
            r.OPTIONS(rt.Path, gin.WrapF(rt.Handler))
        }
    }
    r.Run(":8080")
}
```

### 2. Setup Authentication Routes

Replace the old adapter-based setup with the modular Routes approach above. Middlewares configured by modules are applied during `Initialize`.

## Middleware Integration

### 1. Authentication Middleware

```go
// Custom authentication middleware
func CustomAuthMiddleware(auth *goauth.Auth) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Extract token from header
        token := extractToken(c)
        if token == "" {
            c.JSON(401, gin.H{"error": "Authorization token required"})
            c.Abort()
            return
        }

        // Validate token
        user, err := auth.ValidateToken(token)
        if err != nil {
            c.JSON(401, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        // Set user in context
        c.Set("user", user)
        c.Set("user_id", user.ID)
        c.Set("user_email", user.Email)

        c.Next()
    }
}

// Extract token from various sources
func extractToken(c *gin.Context) string {
    // Check Authorization header
    if token := c.GetHeader("Authorization"); token != "" {
        if strings.HasPrefix(token, "Bearer ") {
            return strings.TrimPrefix(token, "Bearer ")
        }
    }

    // Check query parameter
    if token := c.Query("token"); token != "" {
        return token
    }

    // Check cookie
    if token, err := c.Cookie("auth_token"); err == nil {
        return token
    }

    return ""
}
```

### 2. Role-Based Access Control

```go
// Role-based middleware
func RequireRole(roles ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        user, exists := c.Get("user")
        if !exists {
            c.JSON(401, gin.H{"error": "User not authenticated"})
            c.Abort()
            return
        }

        userRole := user.(*models.User).Role
        for _, role := range roles {
            if userRole == role {
                c.Next()
                return
            }
        }

        c.JSON(403, gin.H{"error": "Insufficient permissions"})
        c.Abort()
    }
}

// Permission-based middleware
func RequirePermission(permissions ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        user, exists := c.Get("user")
        if !exists {
            c.JSON(401, gin.H{"error": "User not authenticated"})
            c.Abort()
            return
        }

        userPermissions := getUserPermissions(user.(*models.User).ID)
        for _, permission := range permissions {
            if !contains(userPermissions, permission) {
                c.JSON(403, gin.H{"error": "Insufficient permissions"})
                c.Abort()
                return
            }
        }

        c.Next()
    }
}
```

### 3. Rate Limiting Middleware

```go
// Rate limiting middleware
func RateLimitMiddleware(limiter *rate.Limiter) gin.HandlerFunc {
    return func(c *gin.Context) {
        if !limiter.Allow() {
            c.JSON(429, gin.H{"error": "Rate limit exceeded"})
            c.Abort()
            return
        }
        c.Next()
    }
}

// IP-based rate limiting
func IPRateLimitMiddleware(requests int, window time.Duration) gin.HandlerFunc {
    limiters := make(map[string]*rate.Limiter)
    mutex := &sync.RWMutex{}

    return func(c *gin.Context) {
        ip := c.ClientIP()

        mutex.Lock()
        limiter, exists := limiters[ip]
        if !exists {
            limiter = rate.NewLimiter(rate.Every(window), requests)
            limiters[ip] = limiter
        }
        mutex.Unlock()

        if !limiter.Allow() {
            c.JSON(429, gin.H{"error": "Rate limit exceeded"})
            c.Abort()
            return
        }

        c.Next()
    }
}
```

## Route Protection

### 1. Protected Routes

```go
// Setup protected routes with different access levels
func setupProtectedRoutes(r *gin.Engine, auth *goauth.Auth) {
    // User routes (authenticated users)
    user := r.Group("/api/user")
    user.Use(auth.AuthMiddleware())
    {
        user.GET("/profile", getUserProfile)
        user.PUT("/profile", updateUserProfile)
        user.GET("/settings", getUserSettings)
        user.PUT("/settings", updateUserSettings)
    }

    // Admin routes (admin users only)
    admin := r.Group("/api/admin")
    admin.Use(auth.AuthMiddleware(), RequireRole("admin"))
    {
        admin.GET("/users", getAllUsers)
        admin.GET("/users/:id", getUserByID)
        admin.PUT("/users/:id", updateUser)
        admin.DELETE("/users/:id", deleteUser)
        admin.GET("/stats", getAdminStats)
    }

    // Super admin routes (super admin only)
    superAdmin := r.Group("/api/super-admin")
    superAdmin.Use(auth.AuthMiddleware(), RequireRole("super_admin"))
    {
        superAdmin.GET("/system", getSystemInfo)
        superAdmin.POST("/maintenance", toggleMaintenance)
        superAdmin.GET("/logs", getSystemLogs)
    }
}
```

### 2. Conditional Route Protection

```go
// Conditional route protection based on user status
func ConditionalAuthMiddleware(auth *goauth.Auth) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Check if route requires authentication
        if requiresAuth(c.Request.URL.Path) {
            auth.AuthMiddleware()(c)
        } else {
            c.Next()
        }
    }
}

// Check if route requires authentication
func requiresAuth(path string) bool {
    publicPaths := []string{
        "/api/auth/login",
        "/api/auth/register",
        "/api/auth/forgot-password",
        "/api/public",
        "/health",
    }

    for _, publicPath := range publicPaths {
        if strings.HasPrefix(path, publicPath) {
            return false
        }
    }

    return true
}
```

## Error Handling

### 1. Custom Error Handler

```go
// Custom error handler for authentication errors
func AuthErrorHandler() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Next()

        // Check for authentication errors
        if len(c.Errors) > 0 {
            for _, err := range c.Errors {
                if isAuthError(err.Err) {
                    handleAuthError(c, err.Err)
                    return
                }
            }
        }
    }
}

// Check if error is authentication-related
func isAuthError(err error) bool {
    authErrors := []string{
        "token expired",
        "invalid token",
        "user not found",
        "insufficient permissions",
        "account locked",
    }

    errMsg := strings.ToLower(err.Error())
    for _, authError := range authErrors {
        if strings.Contains(errMsg, authError) {
            return true
        }
    }

    return false
}

// Handle authentication errors
func handleAuthError(c *gin.Context, err error) {
    errMsg := strings.ToLower(err.Error())

    switch {
    case strings.Contains(errMsg, "token expired"):
        c.JSON(401, gin.H{
            "error": "Token expired",
            "code": "TOKEN_EXPIRED",
            "retry_after": 300, // 5 minutes
        })
    case strings.Contains(errMsg, "invalid token"):
        c.JSON(401, gin.H{
            "error": "Invalid token",
            "code": "INVALID_TOKEN",
        })
    case strings.Contains(errMsg, "insufficient permissions"):
        c.JSON(403, gin.H{
            "error": "Insufficient permissions",
            "code": "INSUFFICIENT_PERMISSIONS",
        })
    case strings.Contains(errMsg, "account locked"):
        c.JSON(423, gin.H{
            "error": "Account locked",
            "code": "ACCOUNT_LOCKED",
            "unlock_time": getUnlockTime(c.GetString("user_id")),
        })
    default:
        c.JSON(500, gin.H{
            "error": "Authentication error",
            "code": "AUTH_ERROR",
        })
    }
}
```

### 2. Error Response Format

```go
// Standard error response format
type ErrorResponse struct {
    Error       string                 `json:"error"`
    Code        string                 `json:"code"`
    Details     map[string]interface{} `json:"details,omitempty"`
    Timestamp   time.Time              `json:"timestamp"`
    RequestID   string                 `json:"request_id,omitempty"`
}

// Create error response
func createErrorResponse(err error, code string, details map[string]interface{}) ErrorResponse {
    return ErrorResponse{
        Error:     err.Error(),
        Code:      code,
        Details:   details,
        Timestamp: time.Now(),
        RequestID: generateRequestID(),
    }
}

// Generate request ID
func generateRequestID() string {
    b := make([]byte, 16)
    rand.Read(b)
    return fmt.Sprintf("%x", b)
}
```

## Performance Optimization

### 1. Caching Middleware

```go
// Caching middleware for user data
func UserCacheMiddleware(cache interfaces.Cache) gin.HandlerFunc {
    return func(c *gin.Context) {
        userID := c.GetString("user_id")
        if userID == "" {
            c.Next()
            return
        }

        // Try to get user from cache
        if cachedUser, err := cache.Get("user:" + userID); err == nil {
            c.Set("user", cachedUser)
            c.Next()
            return
        }

        // User not in cache, continue to handler
        c.Next()

        // Cache user data after handler
        if user, exists := c.Get("user"); exists {
            cache.Set("user:"+userID, user, 5*time.Minute)
        }
    }
}
```

### 2. Connection Pooling

```go
// Database connection pooling
func setupDatabasePool() *sql.DB {
    db, err := sql.Open("postgres", databaseDSN)
    if err != nil {
        log.Fatal("Failed to open database:", err)
    }

    // Set connection pool settings
    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(25)
    db.SetConnMaxLifetime(5 * time.Minute)

    return db
}
```

## Testing

### 1. Unit Tests

```go
func TestGinAuthMiddleware(t *testing.T) {
    // Setup test environment
    auth := setupTestAuth(t)
    r := gin.New()
    r.Use(auth.AuthMiddleware())
    r.GET("/protected", func(c *gin.Context) {
        user := c.Get("user")
        c.JSON(200, gin.H{"user": user})
    })

    // Test without token
    resp := performRequest(r, "GET", "/protected", nil)
    assert.Equal(t, 401, resp.Code)

    // Test with valid token
    token := generateTestToken(t, auth)
    resp = performRequestWithToken(r, "GET", "/protected", nil, token)
    assert.Equal(t, 200, resp.Code)
}

func TestRoleBasedAccess(t *testing.T) {
    // Setup test environment
    auth := setupTestAuth(t)
    r := gin.New()

    adminRoute := r.Group("/admin")
    adminRoute.Use(auth.AuthMiddleware(), RequireRole("admin"))
    adminRoute.GET("/users", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "admin access"})
    })

    // Test with non-admin user
    token := generateTestToken(t, auth, "user")
    resp := performRequestWithToken(r, "GET", "/admin/users", nil, token)
    assert.Equal(t, 403, resp.Code)

    // Test with admin user
    adminToken := generateTestToken(t, auth, "admin")
    resp = performRequestWithToken(r, "GET", "/admin/users", nil, adminToken)
    assert.Equal(t, 200, resp.Code)
}
```

### 2. Integration Tests

```go
func TestGinAuthIntegration(t *testing.T) {
    // Setup test server
    auth := setupTestAuth(t)
    r := setupTestRouter(auth)

    // Test complete authentication flow
    // 1. Register user
    registerResp := performRequest(r, "POST", "/api/auth/register", gin.H{
        "email":    "test@example.com",
        "password": "password123",
        "name":     "Test User",
    })
    assert.Equal(t, 201, registerResp.Code)

    // 2. Login user
    loginResp := performRequest(r, "POST", "/api/auth/login", gin.H{
        "email":    "test@example.com",
        "password": "password123",
    })
    assert.Equal(t, 200, loginResp.Code)

    var loginResult map[string]interface{}
    json.Unmarshal(loginResp.Body.Bytes(), &loginResult)
    token := loginResult["access_token"].(string)

    // 3. Access protected route
    protectedResp := performRequestWithToken(r, "GET", "/api/me", nil, token)
    assert.Equal(t, 200, protectedResp.Code)
}
```

## Best Practices

### 1. Middleware Order

- Place authentication middleware early in the chain
- Order: Logging → Rate Limiting → Authentication → Authorization → Business Logic

### 2. Error Handling

- Use consistent error response formats
- Log authentication failures for security monitoring
- Provide clear error messages to users

### 3. Performance

- Cache user data when appropriate
- Use connection pooling for database connections
- Implement rate limiting to prevent abuse

### 4. Security

- Always validate tokens on the server side
- Use HTTPS in production
- Implement proper session management
- Regular security audits

## Next Steps

- [Echo Framework](echo.md) - Learn about Echo integration
- [Fiber Framework](fiber.md) - Explore Fiber integration
- [Configuration](../configuration/auth.md) - Configure your Gin setup
- [API Reference](../api/endpoints.md) - Explore the complete API
