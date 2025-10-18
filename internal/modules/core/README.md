# Core Module

The **Core Module** is the foundation of GoAuth's modular authentication system. It is automatically registered when you create an auth instance and provides all essential authentication features including user management, sessions, JWT tokens, and verification workflows.

## 🎯 Overview

The Core Module is **auto-registered** and cannot be disabled - it provides the fundamental building blocks that other modules depend on. It handles:

- User registration and authentication
- Session management with JWT tokens
- Password security and reset flows
- Email and phone verification
- Profile management
- Availability checking

## ✨ Features

### 🔐 Authentication

- **User Registration**: Email/password signup with optional username and phone
- **User Login**: Secure authentication with bcrypt password hashing
- **JWT Tokens**: Access and refresh token generation
- **Session Management**: Multi-session support with configurable TTL
- **Logout**: Session termination and token invalidation

### 👤 User Management

- **Profile Management**: View and update user information
- **Extended Attributes**: Store custom user metadata
- **Availability Checking**: Real-time email, username, and phone availability
- **Account Status**: Active/inactive user management

### 🔒 Security

- **Password Hashing**: bcrypt with configurable rounds
- **Password Reset**: Secure token-based password reset flow
- **Password Change**: Authenticated password change with old password verification
- **JWT Security**: Signed tokens with configurable expiry
- **Session Tokens**: Refresh tokens for long-lived sessions

### ✅ Verification

- **Email Verification**: Send and verify email addresses
- **Phone Verification**: Send and verify phone numbers via SMS
- **Verification Tokens**: Time-limited verification tokens
- **Verification Status**: Track verification state per user

## 📦 Auto-Registration

The Core Module is automatically registered when you create an auth instance:

```go
import (
    "github.com/bete7512/goauth/internal/storage"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
)

// Core module is auto-registered here
a, err := auth.New(&config.Config{
    Storage: store,
    Core: &config.CoreConfig{
        RequireEmailVerification: true,
        RequirePhoneVerification: false,
        RequireUserName:          false,
        RequirePhoneNumber:       false,
        UniquePhoneNumber:        true,
    },
})
```

## ⚙️ Configuration

### Core Config Options

```go
type CoreConfig struct {
    // Require email verification during signup
    RequireEmailVerification bool

    // Require phone verification during signup
    RequirePhoneVerification bool

    // Require username field (otherwise optional)
    RequireUserName bool

    // Require phone number field (otherwise optional)
    RequirePhoneNumber bool

    // Ensure phone numbers are unique across users
    UniquePhoneNumber bool
}
```

### Security Config

```go
type SecurityConfig struct {
    // JWT secret for signing tokens (min 32 chars)
    JwtSecretKey string

    // Encryption key for sensitive data (min 32 chars)
    EncryptionKey string

    // Session configuration
    Session SessionConfig
}

type SessionConfig struct {
    // Cookie/header name for session token
    Name string

    // Session duration
    SessionTTL time.Duration

    // Access token expiry (short-lived)
    AccessTokenTTL time.Duration

    // Refresh token expiry (long-lived)
    RefreshTokenTTL time.Duration
}
```

### Frontend Config

```go
type FrontendConfig struct {
    // Frontend URL for redirects and links
    URL string

    // Domain for cookies
    Domain string

    // Path for password reset page
    ResetPasswordPath string

    // Path for email verification callback
    VerifyEmailCallbackPath string

    // Other frontend paths
    LoginPath          string
    SignupPath         string
    LogoutPath         string
    ProfilePath        string
    ChangePasswordPath string
}
```

## 🔌 API Endpoints

All endpoints are prefixed with the configured `BasePath` (default: `/auth`).

### Authentication Endpoints

#### `POST /signup`

Register a new user.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe",
  "username": "johndoe",          // optional unless required
  "phone_number": "+1234567890",  // optional unless required
  "extended_attributes": {        // optional custom data
    "company": "Acme Inc",
    "role": "developer"
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
    "phone_number_verified": false,
    "created_at": "2024-01-01T00:00:00Z"
  },
  "token": "jwt-access-token",
  "refresh_token": "jwt-refresh-token"
}
```

#### `POST /login`

Authenticate a user.

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
  "user": { /* user object */ },
  "token": "jwt-access-token",
  "refresh_token": "jwt-refresh-token"
}
```

#### `POST /logout`

Logout and invalidate session.

**Headers:**
```
Authorization: Bearer <access-token>
```

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

### Profile Endpoints

#### `GET /me`

Get current authenticated user (minimal data).

**Headers:**
```
Authorization: Bearer <access-token>
```

**Response:**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe"
}
```

#### `GET /profile`

Get full user profile.

**Headers:**
```
Authorization: Bearer <access-token>
```

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
    "role": "developer"
  },
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-15T00:00:00Z"
}
```

#### `PUT /profile`

Update user profile.

**Headers:**
```
Authorization: Bearer <access-token>
```

**Request:**
```json
{
  "first_name": "Jane",
  "last_name": "Smith",
  "phone_number": "+9876543210",
  "extended_attributes": {
    "company": "New Company",
    "role": "senior developer"
  }
}
```

**Response:**
```json
{
  "message": "Profile updated successfully",
  "user": { /* updated user object */ }
}
```

### Password Endpoints

#### `PUT /change-password`

Change password (requires authentication).

**Headers:**
```
Authorization: Bearer <access-token>
```

**Request:**
```json
{
  "old_password": "OldPassword123!",
  "new_password": "NewPassword456!"
}
```

**Response:**
```json
{
  "message": "Password changed successfully"
}
```

#### `POST /forgot-password`

Request password reset email.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "message": "Password reset email sent"
}
```

#### `POST /reset-password`

Reset password using token.

**Request:**
```json
{
  "token": "reset-token-from-email",
  "new_password": "NewPassword456!"
}
```

**Response:**
```json
{
  "message": "Password reset successfully"
}
```

### Email Verification

#### `POST /send-verification-email`

Send email verification.

**Headers:**
```
Authorization: Bearer <access-token>
```

**Response:**
```json
{
  "message": "Verification email sent"
}
```

#### `GET /verify-email`

Verify email address (typically called from email link).

**Query Parameters:**
- `token`: Verification token from email

**Response:**
Redirects to frontend `VerifyEmailCallbackPath` with status

### Phone Verification

#### `POST /send-verification-phone`

Send phone verification code.

**Headers:**
```
Authorization: Bearer <access-token>
```

**Response:**
```json
{
  "message": "Verification code sent"
}
```

#### `POST /verify-phone`

Verify phone with code.

**Headers:**
```
Authorization: Bearer <access-token>
```

**Request:**
```json
{
  "code": "123456"
}
```

**Response:**
```json
{
  "message": "Phone verified successfully"
}
```

### Availability Checking

#### `POST /availability/email`

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

#### `POST /availability/username`

Check if username is available.

**Request:**
```json
{
  "username": "newusername"
}
```

**Response:**
```json
{
  "available": false,
  "field": "username",
  "message": "Username already taken"
}
```

#### `POST /availability/phone`

Check if phone number is available.

**Request:**
```json
{
  "phone_number": "+1234567890"
}
```

**Response:**
```json
{
  "available": true,
  "field": "phone_number"
}
```

## 📊 Data Models

### User Model

```go
type User struct {
    ID                    string                 `json:"id"`
    Email                 string                 `json:"email"`
    PasswordHash          string                 `json:"-"` // Never exposed
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
    RefreshToken string    `json:"-"` // Never exposed
    IPAddress    string    `json:"ip_address"`
    UserAgent    string    `json:"user_agent"`
    ExpiresAt    time.Time `json:"expires_at"`
    CreatedAt    time.Time `json:"created_at"`
}
```

### Token Model

```go
type Token struct {
    ID        string    `json:"id"`
    UserID    string    `json:"user_id"`
    Token     string    `json:"-"` // Hashed, never exposed
    Type      string    `json:"type"` // password_reset, email_verification, etc.
    ExpiresAt time.Time `json:"expires_at"`
    CreatedAt time.Time `json:"created_at"`
}
```

## 🎣 Events

The Core Module emits the following events:

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

### Example: Subscribing to Events

```go
import "github.com/bete7512/goauth/pkg/types"

// Log all signups
a.On(types.EventAfterSignup, func(ctx context.Context, e *types.Event) error {
    user := e.Data["user"]
    log.Printf("New user signed up: %+v", user)
    
    // Send to analytics, CRM, etc.
    analytics.Track("user_signup", user)
    
    return nil
})

// Enforce custom validation
a.On(types.EventBeforeSignup, func(ctx context.Context, e *types.Event) error {
    data := e.Data["request"].(map[string]interface{})
    email := data["email"].(string)
    
    // Check against custom blacklist
    if isBlacklisted(email) {
        return fmt.Errorf("email domain not allowed")
    }
    
    return nil
})
```

## 🔐 Middleware

The Core Module registers the following middleware:

### Auth Middleware

Validates JWT tokens and adds user context to requests.

**Applied to routes:**
- All routes with `core.RequireAuth` middleware specified
- Default protected routes: `/me`, `/profile`, `/logout`, `/change-password`, etc.

**Context Values:**
```go
// Access user ID from context
userID := r.Context().Value("user_id").(string)

// Access full user from context (if loaded)
user := r.Context().Value("user").(*models.User)
```

## 🧪 Testing

The Core Module includes comprehensive tests:

```bash
# Run core module tests
go test ./internal/modules/core/...

# Run with coverage
go test -cover ./internal/modules/core/...

# Run specific test
go test -run TestSignup ./internal/modules/core/handlers/
```

## 🔧 Extending the Core Module

While the Core Module is auto-registered, you can extend it by:

1. **Subscribing to events** for custom logic
2. **Adding custom middleware** to core routes
3. **Creating dependent modules** that build on core features
4. **Implementing custom repositories** for storage

### Example: Custom Middleware on Core Routes

```go
import (
    "github.com/bete7512/goauth/internal/middleware"
    "github.com/bete7512/goauth/pkg/types"
)

// Create auth instance
a, _ := auth.New(&config.Config{...})

// Add custom middleware
a.Use(customModule.New(&customModule.Config{
    // This module can register middlewares that apply to core routes
}))

a.Initialize(context.Background())
```

## 📚 Dependencies

The Core Module depends on:

- **Storage**: User, Session, Token repositories
- **Security**: JWT, bcrypt, encryption utilities
- **Events**: Event bus for hooks
- **Logger**: Structured logging

## 🤝 Related Modules

Modules that extend Core Module functionality:

- **Notification**: Email/SMS for verification and notifications
- **Two-Factor**: Additional authentication layer
- **OAuth**: Social login providers
- **Admin**: Admin-specific user management endpoints

## 📄 License

Part of GoAuth - see main project [LICENSE](../../../LICENSE)

---

**The Core Module provides the solid foundation for GoAuth's modular authentication system.**
