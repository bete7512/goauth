---
id: quickstart
title: Quick Start
sidebar_label: Quick Start
sidebar_position: 3
---

# Quick Start

Get up and running with GoAuth in minutes. This guide will walk you through creating a simple authentication system.

## Prerequisites

- Go 1.21+ installed
- GoAuth installed (see [Installation Guide](installation.md))
- Basic knowledge of Go and web development

## Project Setup

### 1. Create a new project

```bash
mkdir goauth-demo
cd goauth-demo
go mod init goauth-demo
```

### 2. Install dependencies

```bash
go get github.com/your-org/goauth
go get github.com/gin-gonic/gin
go get github.com/lib/pq
```

### 3. Create the main application

Create `main.go`:

```go
package main

import (
    "log"
    "github.com/gin-gonic/gin"
    "github.com/your-org/goauth"
    "github.com/your-org/goauth/pkg/config"
)

func main() {
    // Initialize GoAuth configuration
    cfg := &config.Config{
        Database: config.DatabaseConfig{
            Driver: "postgres",
            DSN:    "postgres://username:password@localhost/goauth?sslmode=disable",
        },
        Security: config.SecurityConfig{
            JWTSecret: "your-secret-key-here",
            SessionSecret: "your-session-secret",
        },
    }

    // Initialize GoAuth
    auth, err := goauth.New(cfg)
    if err != nil {
        log.Fatal("Failed to initialize GoAuth:", err)
    }

    // Setup Gin router
    r := gin.Default()

    // Register authentication routes
    auth.SetupRoutes(r)

    // Add a simple protected route
    r.GET("/protected", auth.Middleware(), func(c *gin.Context) {
        user := auth.GetUser(c)
        c.JSON(200, gin.H{
            "message": "Hello, " + user.Email + "!",
            "user_id": user.ID,
        })
    })

    // Start server
    log.Println("Server starting on :8080")
    r.Run(":8080")
}
```

## Database Setup

### 1. Create PostgreSQL database

```sql
CREATE DATABASE goauth;
CREATE USER goauth_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE goauth TO goauth_user;
```

### 2. Run migrations

GoAuth will automatically create the required tables on first run.

## Testing the Application

### 1. Start the server

```bash
go run main.go
```

### 2. Test registration

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123",
    "name": "John Doe"
  }'
```

### 3. Test login

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

### 4. Test protected route

Use the token from the login response:

```bash
curl -X GET http://localhost:8080/protected \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## What's Happening?

1. **Registration**: Creates a new user account with hashed password
2. **Login**: Authenticates user and returns JWT token
3. **Protected Route**: Uses JWT token to verify user identity
4. **Middleware**: Automatically validates tokens and extracts user information

## Next Steps

Now that you have a basic authentication system running:

- [Basic Authentication](getting-started/basic-auth.md) - Learn about authentication flows
- [OAuth Setup](getting-started/oauth-setup.md) - Add social login
- [Configuration](configuration/auth.md) - Customize your setup
- [Security Features](features/security.md) - Add rate limiting and CSRF protection

## Troubleshooting

### Common Issues

- **Database connection failed**: Check your PostgreSQL connection string
- **Port already in use**: Change the port in `r.Run(":8080")`
- **JWT errors**: Ensure your JWT secret is properly set

### Getting Help

- Check the [GitHub Issues](https://github.com/your-org/goauth/issues)
- Review the [Configuration Guide](configuration/auth.md)
- Join our [Discussions](https://github.com/your-org/goauth/discussions)
