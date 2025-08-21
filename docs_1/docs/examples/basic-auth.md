---
id: basic-auth
title: Basic Authentication Example
sidebar_label: Basic Authentication
sidebar_position: 1
---

# Basic Authentication Example

This guide demonstrates how to implement basic email/password authentication with GoAuth using the Gin framework.

## Project Structure

```
goauth-example/
├── main.go
├── go.mod
├── go.sum
├── config/
│   └── config.go
├── handlers/
│   └── auth.go
├── middleware/
│   └── auth.go
├── models/
│   └── user.go
└── templates/
    ├── login.html
    ├── register.html
    └── dashboard.html
```

## Setup

### 1. Initialize Go Module

```bash
mkdir goauth-example
cd goauth-example
go mod init goauth-example
```

### 2. Install Dependencies

```bash
go get github.com/gin-gonic/gin
go get github.com/your-org/goauth
go get github.com/lib/pq
go get github.com/joho/godotenv
```

### 3. Create Environment File

Create `.env` file:

```bash
# Database
DB_DRIVER=postgres
DB_HOST=localhost
DB_PORT=5432
DB_NAME=goauth_example
DB_USER=goauth_user
DB_PASSWORD=secure_password
DB_SSL_MODE=disable

# Security
JWT_SECRET=your-super-secret-jwt-key-here
SESSION_SECRET=your-super-secret-session-key-here

# Server
PORT=8080
ENV=development
```

## Configuration

### config/config.go

```go
package config

import (
    "fmt"
    "os"
    "strconv"
    "time"
    "github.com/joho/godotenv"
    "github.com/your-org/goauth/pkg/config"
)

type Config struct {
    Server   ServerConfig
    Database DatabaseConfig
    Security SecurityConfig
    Email    EmailConfig
}

type ServerConfig struct {
    Port string
    Env  string
}

type DatabaseConfig struct {
    Driver string
    Host   string
    Port   string
    Name   string
    User   string
    Pass   string
    SSLMode string
}

type SecurityConfig struct {
    JWTSecret     string
    SessionSecret string
}

type EmailConfig struct {
    Host     string
    Port     int
    Username string
    Password string
    From     string
}

func Load() (*Config, error) {
    // Load .env file
    if err := godotenv.Load(); err != nil {
        // Continue without .env file
    }

    port, err := strconv.Atoi(getEnv("PORT", "8080"))
    if err != nil {
        port = 8080
    }

    emailPort, err := strconv.Atoi(getEnv("EMAIL_PORT", "587"))
    if err != nil {
        emailPort = 587
    }

    return &Config{
        Server: ServerConfig{
            Port: getEnv("PORT", "8080"),
            Env:  getEnv("ENV", "development"),
        },
        Database: DatabaseConfig{
            Driver:  getEnv("DB_DRIVER", "postgres"),
            Host:    getEnv("DB_HOST", "localhost"),
            Port:    getEnv("DB_PORT", "5432"),
            Name:    getEnv("DB_NAME", "goauth_example"),
            User:    getEnv("DB_USER", "postgres"),
            Pass:    getEnv("DB_PASSWORD", ""),
            SSLMode: getEnv("DB_SSL_MODE", "disable"),
        },
        Security: SecurityConfig{
            JWTSecret:     getEnv("JWT_SECRET", "default-jwt-secret"),
            SessionSecret: getEnv("SESSION_SECRET", "default-session-secret"),
        },
        Email: EmailConfig{
            Host:     getEnv("EMAIL_HOST", "smtp.gmail.com"),
            Port:     emailPort,
            Username: getEnv("EMAIL_USERNAME", ""),
            Password: getEnv("EMAIL_PASSWORD", ""),
            From:     getEnv("EMAIL_FROM", "noreply@example.com"),
        },
    }, nil
}

func (c *Config) GetDatabaseDSN() string {
    switch c.Database.Driver {
    case "postgres":
        return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
            c.Database.User,
            c.Database.Pass,
            c.Database.Host,
            c.Database.Port,
            c.Database.Name,
            c.Database.SSLMode,
        )
    case "mysql":
        return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
            c.Database.User,
            c.Database.Pass,
            c.Database.Host,
            c.Database.Port,
            c.Database.Name,
        )
    default:
        return ""
    }
}

func (c *Config) GetGoAuthConfig() *config.Config {
    return &config.Config{
        Database: config.DatabaseConfig{
            Driver: c.Database.Driver,
            DSN:    c.GetDatabaseDSN(),
            Options: config.DatabaseOptions{
                MaxOpenConns:    25,
                MaxIdleConns:    25,
                ConnMaxLifetime: 5 * time.Minute,
                ConnMaxIdleTime: 1 * time.Minute,
            },
        },
        Security: config.SecurityConfig{
            JWTSecret:        c.Security.JWTSecret,
            SessionSecret:    c.Security.SessionSecret,
            PasswordMinLength: 8,
            JWTExpiration:    24 * time.Hour,
            RefreshExpiration: 7 * 24 * time.Hour,
        },
        Email: config.EmailConfig{
            Provider: "smtp",
            SMTP: config.SMTPConfig{
                Host:     c.Email.Host,
                Port:     c.Email.Port,
                Username: c.Email.Username,
                Password: c.Email.Password,
                FromEmail: c.Email.From,
                FromName:  "GoAuth Example",
            },
        },
    }
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}
```

## Models

### models/user.go

```go
package models

import (
    "time"
)

type User struct {
    ID              string    `json:"id" db:"id"`
    Email           string    `json:"email" db:"email"`
    PasswordHash    string    `json:"-" db:"password_hash"`
    Name            string    `json:"name" db:"name"`
    Phone           string    `json:"phone,omitempty" db:"phone"`
    Role            string    `json:"role" db:"role"`
    EmailVerified   bool      `json:"email_verified" db:"email_verified"`
    PhoneVerified   bool      `json:"phone_verified" db:"phone_verified"`
    TwoFactorEnabled bool     `json:"two_factor_enabled" db:"two_factor_enabled"`
    Status          string    `json:"status" db:"status"`
    CreatedAt       time.Time `json:"created_at" db:"created_at"`
    UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

type RegisterRequest struct {
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required,min=8"`
    Name     string `json:"name" binding:"required"`
    Phone    string `json:"phone,omitempty"`
}

type LoginRequest struct {
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required"`
}

type UpdateProfileRequest struct {
    Name  string `json:"name,omitempty"`
    Phone string `json:"phone,omitempty"`
}

type ChangePasswordRequest struct {
    CurrentPassword string `json:"current_password" binding:"required"`
    NewPassword     string `json:"new_password" binding:"required,min=8"`
}
```

## Handlers

### handlers/auth.go

```go
package handlers

import (
    "net/http"
    "github.com/gin-gonic/gin"
    "github.com/your-org/goauth"
    "goauth-example/models"
)

type AuthHandler struct {
    auth *goauth.Auth
}

func NewAuthHandler(auth *goauth.Auth) *AuthHandler {
    return &AuthHandler{auth: auth}
}

// Register handles user registration
func (h *AuthHandler) Register(c *gin.Context) {
    var req models.RegisterRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error":   "Invalid request data",
            "details": err.Error(),
        })
        return
    }

    // Create user using GoAuth
    user, err := h.auth.Register(c, req)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error":   err.Error(),
        })
        return
    }

    c.JSON(http.StatusCreated, gin.H{
        "success": true,
        "message": "User registered successfully",
        "user":    user,
    })
}

// Login handles user authentication
func (h *AuthHandler) Login(c *gin.Context) {
    var req models.LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error":   "Invalid request data",
            "details": err.Error(),
        })
        return
    }

    // Authenticate user using GoAuth
    result, err := h.auth.Login(c, req.Email, req.Password)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{
            "success": false,
            "error":   "Invalid credentials",
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success":      true,
        "message":      "Login successful",
        "access_token": result.AccessToken,
        "refresh_token": result.RefreshToken,
        "expires_in":   result.ExpiresIn,
        "user":         result.User,
    })
}

// Logout handles user logout
func (h *AuthHandler) Logout(c *gin.Context) {
    userID := c.GetString("user_id")
    if userID == "" {
        c.JSON(http.StatusUnauthorized, gin.H{
            "success": false,
            "error":   "User not authenticated",
        })
        return
    }

    // Logout user using GoAuth
    err := h.auth.Logout(c, userID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{
            "success": false,
            "error":   "Failed to logout",
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": "Logged out successfully",
    })
}

// GetProfile returns current user's profile
func (h *AuthHandler) GetProfile(c *gin.Context) {
    userID := c.GetString("user_id")
    if userID == "" {
        c.JSON(http.StatusUnauthorized, gin.H{
            "success": false,
            "error":   "User not authenticated",
        })
        return
    }

    // Get user profile using GoAuth
    user, err := h.auth.GetUserByID(c, userID)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{
            "success": false,
            "error":   "User not found",
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "user":    user,
    })
}

// UpdateProfile updates user profile
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
    userID := c.GetString("user_id")
    if userID == "" {
        c.JSON(http.StatusUnauthorized, gin.H{
            "success": false,
            "error":   "User not authenticated",
        })
        return
    }

    var req models.UpdateProfileRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error":   "Invalid request data",
            "details": err.Error(),
        })
        return
    }

    // Update user profile using GoAuth
    user, err := h.auth.UpdateProfile(c, userID, req)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{
            "success": false,
            "error":   "Failed to update profile",
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": "Profile updated successfully",
        "user":    user,
    })
}

// ChangePassword changes user password
func (h *AuthHandler) ChangePassword(c *gin.Context) {
    userID := c.GetString("user_id")
    if userID == "" {
        c.JSON(http.StatusUnauthorized, gin.H{
            "success": false,
            "error":   "User not authenticated",
        })
        return
    }

    var req models.ChangePasswordRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error":   "Invalid request data",
            "details": err.Error(),
        })
        return
    }

    // Change password using GoAuth
    err := h.auth.ChangePassword(c, userID, req.CurrentPassword, req.NewPassword)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error":   err.Error(),
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": "Password changed successfully",
    })
}

// ForgotPassword handles password reset request
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
    var req struct {
        Email string `json:"email" binding:"required,email"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error":   "Invalid email address",
        })
        return
    }

    // Send password reset email using GoAuth
    err := h.auth.ForgotPassword(c, req.Email)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error":   err.Error(),
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": "Password reset email sent",
    })
}

// ResetPassword handles password reset
func (h *AuthHandler) ResetPassword(c *gin.Context) {
    var req struct {
        Token    string `json:"token" binding:"required"`
        Password string `json:"password" binding:"required,min=8"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error":   "Invalid request data",
        })
        return
    }

    // Reset password using GoAuth
    err := h.auth.ResetPassword(c, req.Token, req.Password)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error":   err.Error(),
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": "Password reset successfully",
    })
}
```

## Middleware

### middleware/auth.go

```go
package middleware

import (
    "net/http"
    "strings"
    "github.com/gin-gonic/gin"
    "github.com/your-org/goauth"
)

// AuthMiddleware validates JWT tokens and sets user context
func AuthMiddleware(auth *goauth.Auth) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Extract token from header
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{
                "success": false,
                "error":   "Authorization header required",
            })
            c.Abort()
            return
        }

        // Parse Bearer token
        token := strings.TrimPrefix(authHeader, "Bearer ")
        if token == authHeader {
            c.JSON(http.StatusUnauthorized, gin.H{
                "success": false,
                "error":   "Bearer token required",
            })
            c.Abort()
            return
        }

        // Validate token using GoAuth
        user, err := auth.ValidateToken(token)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{
                "success": false,
                "error":   "Invalid token",
            })
            c.Abort()
            return
        }

        // Set user in context
        c.Set("user", user)
        c.Set("user_id", user.ID)
        c.Set("user_email", user.Email)
        c.Set("user_role", user.Role)

        c.Next()
    }
}

// RequireRole middleware checks if user has required role
func RequireRole(roles ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        userRole, exists := c.Get("user_role")
        if !exists {
            c.JSON(http.StatusUnauthorized, gin.H{
                "success": false,
                "error":   "User role not found",
            })
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

        c.JSON(http.StatusForbidden, gin.H{
            "success": false,
            "error":   "Insufficient permissions",
        })
        c.Abort()
    }
}

// RateLimitMiddleware implements basic rate limiting
func RateLimitMiddleware(requests int, window time.Duration) gin.HandlerFunc {
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
            c.JSON(http.StatusTooManyRequests, gin.H{
                "success": false,
                "error":   "Rate limit exceeded",
            })
            c.Abort()
            return
        }

        c.Next()
    }
}
```

## Main Application

### main.go

```go
package main

import (
    "log"
    "github.com/gin-gonic/gin"
    "github.com/your-org/goauth"
    "goauth-example/config"
    "goauth-example/handlers"
    "goauth-example/middleware"
)

func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        log.Fatal("Failed to load configuration:", err)
    }

    // Initialize GoAuth
    auth, err := goauth.New(cfg.GetGoAuthConfig())
    if err != nil {
        log.Fatal("Failed to initialize GoAuth:", err)
    }

    // Create Gin router
    if cfg.Server.Env == "production" {
        gin.SetMode(gin.ReleaseMode)
    }
    r := gin.Default()

    // Setup middleware
    r.Use(gin.Logger())
    r.Use(gin.Recovery())
    r.Use(middleware.CORS())

    // Setup routes
    setupRoutes(r, auth, cfg)

    // Start server
    log.Printf("Server starting on port %s", cfg.Server.Port)
    if err := r.Run(":" + cfg.Server.Port); err != nil {
        log.Fatal("Failed to start server:", err)
    }
}

func setupRoutes(r *gin.Engine, auth *goauth.Auth, cfg *config.Config) {
    // Health check
    r.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "status": "healthy",
            "service": "goauth-example",
        })
    })

    // API routes
    api := r.Group("/api")
    {
        // Public routes
        public := api.Group("/auth")
        {
            public.POST("/register", middleware.RateLimitMiddleware(5, time.Minute), handlers.NewAuthHandler(auth).Register)
            public.POST("/login", middleware.RateLimitMiddleware(5, time.Minute), handlers.NewAuthHandler(auth).Login)
            public.POST("/forgot-password", middleware.RateLimitMiddleware(3, time.Hour), handlers.NewAuthHandler(auth).ForgotPassword)
            public.POST("/reset-password", handlers.NewAuthHandler(auth).ResetPassword)
        }

        // Protected routes
        protected := api.Group("/auth")
        protected.Use(middleware.AuthMiddleware(auth))
        {
            protected.POST("/logout", handlers.NewAuthHandler(auth).Logout)
            protected.GET("/profile", handlers.NewAuthHandler(auth).GetProfile)
            protected.PUT("/profile", handlers.NewAuthHandler(auth).UpdateProfile)
            protected.PUT("/change-password", handlers.NewAuthHandler(auth).ChangePassword)
        }

        // Admin routes
        admin := api.Group("/admin")
        admin.Use(middleware.AuthMiddleware(auth), middleware.RequireRole("admin"))
        {
            admin.GET("/users", handlers.NewAdminHandler(auth).GetUsers)
            admin.PUT("/users/:id/role", handlers.NewAdminHandler(auth).UpdateUserRole)
        }
    }

    // Web routes (if you want to serve HTML pages)
    if cfg.Server.Env == "development" {
        r.LoadHTMLGlob("templates/*")
        r.Static("/static", "./static")

        web := r.Group("/")
        {
            web.GET("/", handlers.NewWebHandler(auth).Home)
            web.GET("/login", handlers.NewWebHandler(auth).LoginPage)
            web.GET("/register", handlers.NewWebHandler(auth).RegisterPage)
            web.GET("/dashboard", middleware.AuthMiddleware(auth), handlers.NewWebHandler(auth).Dashboard)
        }
    }
}
```

## Database Setup

### Create Database

```sql
-- Create database
CREATE DATABASE goauth_example;

-- Create user
CREATE USER goauth_user WITH PASSWORD 'secure_password';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE goauth_example TO goauth_user;

-- Connect to database
\c goauth_example

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```

### Run Migrations

GoAuth will automatically create the required tables on first run, or you can run migrations manually:

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    role VARCHAR(50) DEFAULT 'user',
    email_verified BOOLEAN DEFAULT FALSE,
    phone_verified BOOLEAN DEFAULT FALSE,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tokens table
CREATE TABLE tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_phone ON users(phone);
CREATE INDEX idx_tokens_user_id ON tokens(user_id);
CREATE INDEX idx_tokens_value ON tokens(value);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(token);
```

## Testing

### Test the API

1. **Start the server:**

```bash
go run main.go
```

2. **Register a new user:**

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "name": "Test User"
  }'
```

3. **Login:**

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

4. **Get profile (using token from login):**

```bash
curl -X GET http://localhost:8080/api/auth/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

5. **Update profile:**

```bash
curl -X PUT http://localhost:8080/api/auth/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Name"
  }'
```

## Frontend Templates

### templates/login.html

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Login - GoAuth Example</title>
    <link rel="stylesheet" href="/static/css/style.css" />
  </head>
  <body>
    <div class="container">
      <div class="auth-form">
        <h2>Login</h2>
        <form id="loginForm">
          <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" required />
          </div>
          <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required />
          </div>
          <button type="submit">Login</button>
        </form>
        <p>Don't have an account? <a href="/register">Register</a></p>
        <p><a href="/forgot-password">Forgot Password?</a></p>
      </div>
    </div>

    <script>
      document
        .getElementById("loginForm")
        .addEventListener("submit", async function (e) {
          e.preventDefault();

          const formData = new FormData(this);
          const data = {
            email: formData.get("email"),
            password: formData.get("password"),
          };

          try {
            const response = await fetch("/api/auth/login", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify(data),
            });

            const result = await response.json();

            if (result.success) {
              // Store token
              localStorage.setItem("access_token", result.access_token);
              // Redirect to dashboard
              window.location.href = "/dashboard";
            } else {
              alert(result.error);
            }
          } catch (error) {
            alert("Login failed: " + error.message);
          }
        });
    </script>
  </body>
</html>
```

## Error Handling

### Common Error Scenarios

1. **Invalid credentials:**

```json
{
  "success": false,
  "error": "Invalid credentials"
}
```

2. **Email already exists:**

```json
{
  "success": false,
  "error": "Email already exists"
}
```

3. **Token expired:**

```json
{
  "success": false,
  "error": "Token expired"
}
```

4. **Insufficient permissions:**

```json
{
  "success": false,
  "error": "Insufficient permissions"
}
```

## Security Considerations

### 1. Environment Variables

- Store sensitive configuration in environment variables
- Use strong, unique secrets for each environment
- Never commit secrets to version control

### 2. Rate Limiting

- Implement rate limiting for authentication endpoints
- Use different limits for different operations
- Monitor for suspicious activity

### 3. Input Validation

- Validate all input data
- Use GoAuth's built-in validation
- Sanitize user inputs

### 4. HTTPS

- Use HTTPS in production
- Set secure cookies
- Implement proper CORS policies

## Next Steps

- [OAuth Integration](oauth-setup.md) - Add social login
- [Two-Factor Authentication](two-factor.md) - Implement 2FA
- [Advanced Security](security.md) - Add security features
- [Testing](testing.md) - Write tests for your application
