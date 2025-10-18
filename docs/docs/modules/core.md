---
id: core
title: Core Module
sidebar_label: Core Module  
sidebar_position: 1
---

# Core Module

The **Core Module** is the foundation of GoAuth. It is **automatically registered** when you create an auth instance and provides all essential authentication features.

## Overview

The Core Module cannot be disabled - it provides the fundamental building blocks that other modules depend on. Every GoAuth application includes the Core Module by default.

## Features

### 🔐 User Authentication
- **Registration**: Email/password signup with optional username and phone
- **Login**: Secure authentication with bcrypt password hashing
- **Logout**: Session termination and token invalidation
- **JWT Tokens**: Access and refresh token generation with configurable expiry

### 👤 User Management
- **Profile Management**: View and update user information
- **Extended Attributes**: Store custom user metadata as JSON
- **Availability Checking**: Real-time email, username, and phone availability
- **Account Status**: Active/inactive user management

### 🔒 Password Security
- **Password Hashing**: bcrypt with configurable rounds
- **Password Reset**: Secure token-based password reset flow
- **Password Change**: Authenticated password change with old password verification

### ✅ Verification
- **Email Verification**: Send and verify email addresses
- **Phone Verification**: Send and verify phone numbers via SMS (requires Notification module)
- **Verification Tokens**: Time-limited, one-time-use tokens

## Configuration

### Basic Configuration

```go
a, _ := auth.New(&config.Config{
    Storage:     store,
    AutoMigrate: true,
    BasePath:    "/api/v1",
    
    // Core module configuration
    Core: &config.CoreConfig{
        RequireEmailVerification: true,   // Require email verification on signup
        RequirePhoneVerification: false,  // Require phone verification on signup
        RequireUserName:          false,  // Make username field required
        RequirePhoneNumber:       false,  // Make phone field required
        UniquePhoneNumber:        true,   // Ensure phone numbers are unique
    },
    
    // Security configuration
    Security: types.SecurityConfig{
        JwtSecretKey:  "your-secret-key-min-32-chars!!!!",
        EncryptionKey: "your-encryption-key-32-chars!",
        Session: types.SessionConfig{
            Name:            "session_token",
            SessionTTL:      30 * 24 * time.Hour,  // Session duration
            AccessTokenTTL:  15 * time.Minute,      // Short-lived access token
            RefreshTokenTTL: 7 * 24 * time.Hour,   // Long-lived refresh token
        },
    },
    
    // Frontend configuration
    FrontendConfig: &config.FrontendConfig{
        URL:                     "http://localhost:3000",
        Domain:                  "localhost",
        VerifyEmailCallbackPath: "/verify-email",
        ResetPasswordPath:       "/reset-password",
        LoginPath:               "/login",
    },
})
```

### Configuration Options

#### Core Config

```go
type CoreConfig struct {
    // Require email verification during signup
    RequireEmailVerification bool

    // Require phone verification during signup (needs Notification module)
    RequirePhoneVerification bool

    // Require username field (otherwise optional)
    RequireUserName bool

    // Require phone number field (otherwise optional)
    RequirePhoneNumber bool

    // Ensure phone numbers are unique across users
    UniquePhoneNumber bool
}
```

#### Security Config

```go
type SecurityConfig struct {
    // JWT secret for signing tokens (minimum 32 characters)
    JwtSecretKey string

    // Encryption key for sensitive data (minimum 32 characters)
    EncryptionKey string

    // Session configuration
    Session SessionConfig
}

type SessionConfig struct {
    // Cookie/header name for session token
    Name string

    // Total session duration
    SessionTTL time.Duration

    // Access token expiry (short-lived, e.g., 15 minutes)
    AccessTokenTTL time.Duration

    // Refresh token expiry (long-lived, e.g., 7 days)
    RefreshTokenTTL time.Duration
}
```

## API Endpoints

All endpoints are prefixed with your configured `BasePath` (default: `/auth`).

### Authentication Endpoints

#### POST `/signup`

Register a new user account.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe",
  "username": "johndoe",           // optional unless required
  "phone_number": "+1234567890",   // optional unless required
  "extended_attributes": {          // optional custom data
    "company": "Acme Inc",
    "department": "Engineering"
  }
}
```

**Response:**
```json
{
  "message": "User registered successfully",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "username": "johndoe",
    "email_verified": false,
    "phone_number_verified": false
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### POST `/login`

Authenticate a user and receive tokens.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "first_name": "John"
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### POST `/logout`

Logout and invalidate session.

**Headers:** `Authorization: Bearer <access-token>`

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

### Profile Endpoints

#### GET `/me`

Get current authenticated user (minimal data).

**Headers:** `Authorization: Bearer <access-token>`

**Response:**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe"
}
```

#### GET `/profile`

Get full user profile with extended attributes.

**Headers:** `Authorization: Bearer <access-token>`

**Response:**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "username": "johndoe",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1234567890",
  "email_verified": true,
  "phone_number_verified": false,
  "extended_attributes": {
    "company": "Acme Inc",
    "department": "Engineering"
  },
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-15T00:00:00Z"
}
```

#### PUT `/profile`

Update user profile.

**Headers:** `Authorization: Bearer <access-token>`

**Request:**
```json
{
  "first_name": "Jane",
  "last_name": "Smith",
  "phone_number": "+9876543210",
  "extended_attributes": {
    "company": "New Company",
    "role": "Manager"
  }
}
```

### Password Endpoints

#### PUT `/change-password`

Change password (requires authentication).

**Headers:** `Authorization: Bearer <access-token>`

**Request:**
```json
{
  "old_password": "OldPassword123!",
  "new_password": "NewPassword456!"
}
```

#### POST `/forgot-password`

Request password reset email.

**Request:**
```json
{
  "email": "user@example.com"
}
```

#### POST `/reset-password`

Reset password using token from email.

**Request:**
```json
{
  "token": "reset-token-from-email",
  "new_password": "NewPassword456!"
}
```

### Email Verification

#### POST `/send-verification-email`

Send email verification link.

**Headers:** `Authorization: Bearer <access-token>`

#### GET `/verify-email`

Verify email address (called from email link).

**Query:** `?token=verification-token`

Redirects to frontend with status.

### Phone Verification

#### POST `/send-verification-phone`

Send phone verification code via SMS (requires Notification module).

**Headers:** `Authorization: Bearer <access-token>`

#### POST `/verify-phone`

Verify phone number with code.

**Headers:** `Authorization: Bearer <access-token>`

**Request:**
```json
{
  "code": "123456"
}
```

### Availability Checking

#### POST `/availability/email`

Check if email is available.

**Request:**
```json
{
  "email": "newuser@example.com"
}
```

**Response:**
```json
{
  "available": true,
  "field": "email"
}
```

#### POST `/availability/username`

Check if username is available.

#### POST `/availability/phone`

Check if phone number is available.

## Events

The Core Module emits these events for custom logic:

### Authentication Events
- `EventBeforeSignup` - Before user registration
- `EventAfterSignup` - After successful registration
- `EventBeforeLogin` - Before user login
- `EventAfterLogin` - After successful login
- `EventBeforeLogout` - Before user logout
- `EventAfterLogout` - After successful logout

### Password Events
- `EventBeforePasswordReset` - Before password reset request
- `EventAfterPasswordReset` - After password reset
- `EventBeforePasswordChange` - Before password change
- `EventAfterPasswordChange` - After password change

### Profile Events
- `EventBeforeProfileUpdate` - Before profile update
- `EventAfterProfileUpdate` - After profile update

### Verification Events
- `EventBeforeEmailVerification` - Before email verification
- `EventAfterEmailVerification` - After email verification
- `EventBeforePhoneVerification` - Before phone verification
- `EventAfterPhoneVerification` - After phone verification

### Using Events

```go
import "github.com/bete7512/goauth/pkg/types"

// Subscribe to signup event
a.On(types.EventAfterSignup, func(ctx context.Context, e *types.Event) error {
    user := e.Data["user"]
    log.Printf("New user registered: %+v", user)
    
    // Send to analytics
    analytics.Track("user_signup", user)
    
    return nil
})

// Enforce custom validation
a.On(types.EventBeforeSignup, func(ctx context.Context, e *types.Event) error {
    data := e.Data["request"].(map[string]interface{})
    email := data["email"].(string)
    
    // Custom validation logic
    if isBlacklisted(email) {
        return fmt.Errorf("email domain not allowed")
    }
    
    return nil
})
```

## Data Models

### User Model

```go
type User struct {
    ID                    string                 `json:"id"`
    Email                 string                 `json:"email"`
    Username              *string                `json:"username,omitempty"`
    FirstName             string                 `json:"first_name"`
    LastName              string                 `json:"last_name"`
    PhoneNumber           *string                `json:"phone_number,omitempty"`
    EmailVerified         bool                   `json:"email_verified"`
    PhoneNumberVerified   bool                   `json:"phone_number_verified"`
    Active                bool                   `json:"active"`
    ExtendedAttributes    map[string]interface{} `json:"extended_attributes,omitempty"`
    CreatedAt             time.Time              `json:"created_at"`
    UpdatedAt             time.Time              `json:"updated_at"`
}
```

### Session Model

```go
type Session struct {
    ID           string    `json:"id"`
    UserID       string    `json:"user_id"`
    IPAddress    string    `json:"ip_address"`
    UserAgent    string    `json:"user_agent"`
    ExpiresAt    time.Time `json:"expires_at"`
    CreatedAt    time.Time `json:"created_at"`
}
```

## Security Best Practices

1. **Use Strong Secrets**: Minimum 32 random characters for JWT and encryption keys
2. **Enable HTTPS**: Always use HTTPS in production
3. **Short Access Tokens**: Keep access tokens short-lived (15 minutes)
4. **Longer Refresh Tokens**: Use longer-lived refresh tokens (7 days)
5. **Email Verification**: Enable `RequireEmailVerification` in production
6. **Strong Passwords**: Enforce password policies in your frontend
7. **Rate Limiting**: Add the Rate Limiter module to prevent brute force
8. **CSRF Protection**: Add the CSRF module for web applications

## Next Steps

- **[Notification Module](notification.md)** - Add email/SMS notifications
- **[Two-Factor Module](#)** - Enhance security with 2FA
- **[OAuth Module](#)** - Add social login
- **[API Reference](/docs/api/endpoints)** - Complete API documentation

---

**The Core Module provides the solid foundation for all GoAuth applications.**

