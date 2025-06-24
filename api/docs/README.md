# GoAuth API Documentation

This directory contains comprehensive Swagger/OpenAPI documentation for the GoAuth authentication and authorization API.

## Structure

```
docs/
├── README.md                 # This file
├── swagger.go               # Main Swagger documentation generator
├── server.go                # Server configuration documentation
├── api/                     # API endpoint documentation
│   ├── login.go             # Login endpoint docs
│   ├── register.go          # Registration endpoint docs
│   ├── logout.go            # Logout endpoint docs
│   ├── refreshToken.go      # Token refresh endpoint docs
│   ├── forgetPassword.go    # Password reset request docs
│   ├── resetPassword.go     # Password reset docs
│   ├── updateProfile.go     # Profile update docs
│   ├── getMe.go             # Get current user docs
│   ├── deactivateUser.go    # User deactivation docs
│   ├── twoFactor.go         # 2FA endpoints docs
│   ├── emailVerification.go # Email verification docs
│   ├── magicLink.go         # Magic link authentication docs
│   └── oauth/               # OAuth provider documentation
│       ├── google.go        # Google OAuth docs
│       ├── github.go        # GitHub OAuth docs
│       ├── facebook.go      # Facebook OAuth docs
│       └── microsoft.go     # Microsoft OAuth docs
└── definations/             # Schema definitions
    ├── user.go              # User model definition
    ├── request.go           # Request model definitions
    ├── response.go          # Response model definitions
    └── error.go             # Error model definition
```

## Features

### Authentication Endpoints
- **POST /register** - User registration
- **POST /login** - User login with email/password
- **POST /logout** - User logout
- **POST /refresh-token** - Refresh access token
- **POST /forgot-password** - Request password reset
- **POST /reset-password** - Reset password with token
- **POST /magic-link** - Send magic link for passwordless auth
- **GET /magic-link/callback** - Verify magic link

### User Management
- **GET /me** - Get current user profile
- **POST /update-profile** - Update user profile
- **POST /deactivate-user** - Deactivate user account

### Two-Factor Authentication
- **POST /enable-two-factor** - Enable 2FA
- **POST /verify-two-factor** - Verify 2FA code
- **POST /disable-two-factor** - Disable 2FA

### Email Verification
- **GET /verify-email** - Verify email with token
- **POST /resend-verification-email** - Resend verification email

### OAuth Providers
- **Google OAuth** - `/oauth/google` and `/oauth/google/callback`
- **GitHub OAuth** - `/oauth/github` and `/oauth/github/callback`
- **Facebook OAuth** - `/oauth/facebook` and `/oauth/facebook/callback`
- **Microsoft OAuth** - `/oauth/microsoft` and `/oauth/microsoft/callback`

## Usage

### Generating Documentation

The Swagger documentation is generated programmatically using the `docs.SwaggerDoc()` function:

```go
import "github.com/bete7512/goauth/docs"

// Create Swagger info
info := docs.SwaggerInfo{
    Title:       "My Auth API",
    Description: "Authentication API for my application",
    Version:     "1.0.0",
    Host:        "api.example.com",
    BasePath:    "/api/v1",
    Schemes:     []string{"https"},
}

// Generate documentation
swaggerDoc := docs.SwaggerDoc(info)
```

### Framework Integration

The documentation works with all supported frameworks:

#### Gin
```go
import "github.com/gin-gonic/gin"

router := gin.Default()
router.GET("/docs", func(c *gin.Context) {
    c.JSON(200, docs.SwaggerDoc(info))
})
```

#### Echo
```go
import "github.com/labstack/echo/v4"

e := echo.New()
e.GET("/docs", func(c echo.Context) error {
    return c.JSON(200, docs.SwaggerDoc(info))
})
```

#### Chi
```go
import "github.com/go-chi/chi/v5"

r := chi.NewRouter()
r.Get("/docs", func(w http.ResponseWriter, r *http.Request) {
    json.NewEncoder(w).Encode(docs.SwaggerDoc(info))
})
```

#### Fiber
```go
import "github.com/gofiber/fiber/v2"

app := fiber.New()
app.Get("/docs", func(c *fiber.Ctx) error {
    return c.JSON(docs.SwaggerDoc(info))
})
```

#### Standard HTTP
```go
http.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(docs.SwaggerDoc(info))
})
```

## Schema Definitions

### User Model
```json
{
  "id": "string",
  "email": "string",
  "first_name": "string",
  "last_name": "string",
  "phone_number": "string",
  "is_verified": "boolean",
  "is_active": "boolean",
  "created_at": "string",
  "updated_at": "string"
}
```

### Error Response
```json
{
  "error": "string",
  "message": "string",
  "status_code": "integer"
}
```

### Authentication Response
```json
{
  "message": "string",
  "access_token": "string",
  "refresh_token": "string",
  "user": {
    "$ref": "#/definitions/User"
  }
}
```

## Security

The API uses Bearer token authentication:

```
Authorization: Bearer <access_token>
```

## Rate Limiting

All endpoints are protected by rate limiting middleware. The limits are configurable per endpoint.

## CORS

The API supports CORS for cross-origin requests. Configuration is handled by the framework-specific middleware.

## Examples

### Register a new user
```bash
curl -X POST http://localhost:8080/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "password": "Password123!"
  }'
```

### Login
```bash
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "Password123!"
  }'
```

### Get current user
```bash
curl -X GET http://localhost:8080/api/v1/me \
  -H "Authorization: Bearer <access_token>"
```

## Contributing

When adding new endpoints:

1. Create a new file in `docs/api/` for the endpoint
2. Add the endpoint to the `Paths()` function in `docs/swagger.go`
3. Add any new request/response definitions to `docs/definations/`
4. Update this README if needed

## License

This documentation is part of the GoAuth project and follows the same license. 