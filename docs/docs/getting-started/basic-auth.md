---
id: basic-auth
title: Basic Authentication
sidebar_label: Basic Authentication
sidebar_position: 1
---

# Basic Authentication

Learn how to implement basic email/password authentication with GoAuth.

## Overview

Basic authentication in GoAuth handles user registration, login, logout, and password management. It provides a secure foundation for user account management with features like password hashing, email verification, and password reset.

## Core Components

### 1. User Registration

```go
type RegisterRequest struct {
    Email     string `json:"email" binding:"required,email"`
    Password  string `json:"password" binding:"required,min=8"`
    Name      string `json:"name" binding:"required"`
    Phone     string `json:"phone,omitempty"`
}
```

**Example Registration:**

```go
// Register a new user
func registerUser(c *gin.Context) {
    var req RegisterRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    user, err := auth.Register(c, req)
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    c.JSON(201, gin.H{
        "message": "User registered successfully",
        "user_id": user.ID,
    })
}
```

### 2. User Login

```go
type LoginRequest struct {
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required"`
}
```

**Example Login:**

```go
// Login user
func loginUser(c *gin.Context) {
    var req LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    result, err := auth.Login(c, req)
    if err != nil {
        c.JSON(401, gin.H{"error": "Invalid credentials"})
        return
    }

    c.JSON(200, gin.H{
        "access_token": result.AccessToken,
        "refresh_token": result.RefreshToken,
        "user": result.User,
    })
}
```

### 3. Authentication Middleware

```go
// Protected route example
func protectedRoute(c *gin.Context) {
    user := auth.GetUser(c)
    c.JSON(200, gin.H{
        "message": "Hello, " + user.Name + "!",
        "user_id": user.ID,
        "email": user.Email,
    })
}

// Setup routes with middleware
r.GET("/protected", auth.Middleware(), protectedRoute)
```

## Password Management

### Password Reset

```go
// Request password reset
func requestPasswordReset(c *gin.Context) {
    var req struct {
        Email string `json:"email" binding:"required,email"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    err := auth.ForgetPassword(c, req.Email)
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    c.JSON(200, gin.H{
        "message": "Password reset email sent",
    })
}

// Reset password with token
func resetPassword(c *gin.Context) {
    var req struct {
        Token    string `json:"token" binding:"required"`
        Password string `json:"password" binding:"required,min=8"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    err := auth.ResetPassword(c, req.Token, req.Password)
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    c.JSON(200, gin.H{
        "message": "Password reset successfully",
    })
}
```

## Email Verification

GoAuth provides built-in email verification through the notification module. The verification flow works as follows:

1. User receives an email with a verification link
2. User clicks the link which goes directly to the backend: `GET /api/auth/verify-email?token=xxx`
3. Backend verifies the token and redirects to the frontend with status

### Configuration

Configure the frontend URL in your auth setup:

```go
authInstance, err := auth.New(&config.Config{
    // ... other config
    FrontendConfig: &config.FrontendConfig{
        URL:             "http://localhost:3000",
        VerifyEmailPath: "/verify-email",
    },
})
```

### Send Verification Email

The notification module handles sending verification emails automatically, or you can trigger it manually:

```go
func sendVerificationEmail(c *gin.Context) {
    user := auth.GetUser(c)

    err := auth.SendEmailVerification(c, user.ID)
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    c.JSON(200, gin.H{
        "message": "Verification email sent",
    })
}
```

### Frontend Verification Page

Create a frontend page at `/verify-email` to handle the redirect:

```typescript
// Example Next.js page
export default function VerifyEmail() {
  const searchParams = useSearchParams()
  const status = searchParams.get('status')
  const message = searchParams.get('message')

  return (
    <div>
      {status === 'success' ? (
        <p>✅ {message}</p>
      ) : (
        <p>❌ {message}</p>
      )}
    </div>
  )
}
```

## Session Management

### Refresh Token

```go
func refreshToken(c *gin.Context) {
    var req struct {
        RefreshToken string `json:"refresh_token" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    result, err := auth.RefreshToken(c, req.RefreshToken)
    if err != nil {
        c.JSON(401, gin.H{"error": "Invalid refresh token"})
        return
    }

    c.JSON(200, gin.H{
        "access_token": result.AccessToken,
        "refresh_token": result.RefreshToken,
    })
}
```

### Logout

```go
func logout(c *gin.Context) {
    user := auth.GetUser(c)

    err := auth.Logout(c, user.ID)
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    c.JSON(200, gin.H{
        "message": "Logged out successfully",
    })
}
```

## Configuration

### Basic Configuration

```go
cfg := &config.Config{
    Database: config.DatabaseConfig{
        Driver: "postgres",
        DSN:    "postgres://user:pass@localhost/goauth?sslmode=disable",
    },
    Security: config.SecurityConfig{
        JWTSecret:        "your-jwt-secret",
        SessionSecret:    "your-session-secret",
        PasswordMinLength: 8,
        JWTExpiration:    24 * time.Hour,
    },
    Email: config.EmailConfig{
        Provider: "smtp",
        SMTP: config.SMTPConfig{
            Host:     "smtp.gmail.com",
            Port:     587,
            Username: "your-email@gmail.com",
            Password: "your-app-password",
        },
    },
}
```

## Security Features

- **Password Hashing**: Uses bcrypt for secure password storage
- **JWT Tokens**: Secure token-based authentication
- **CSRF Protection**: Built-in CSRF token validation
- **Rate Limiting**: Configurable rate limiting for auth endpoints
- **Input Validation**: Comprehensive request validation

## Error Handling

GoAuth provides detailed error responses for various scenarios:

```go
// Common error responses
{
    "error": "Email already exists",
    "code": "EMAIL_EXISTS"
}

{
    "error": "Invalid credentials",
    "code": "INVALID_CREDENTIALS"
}

{
    "error": "Token expired",
    "code": "TOKEN_EXPIRED"
}
```

## Next Steps

- [OAuth Setup](oauth-setup.md) - Add social login capabilities
- [Custom Storage](custom-storage.md) - Implement custom data storage
- [Security Features](../features/security.md) - Learn about advanced security features
- [Configuration](../configuration/auth.md) - Customize your authentication setup
