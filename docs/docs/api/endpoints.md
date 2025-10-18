---
id: endpoints
title: API Endpoints
sidebar_label: Endpoints
sidebar_position: 1
---

# API Endpoints

GoAuth provides a comprehensive REST API for all authentication operations. This document describes all available endpoints, their parameters, and responses.

## Base URL

All API endpoints are prefixed with `/api/auth`:

```
https://yourdomain.com/api/auth
```

## Authentication

### Register User

**POST** `/api/auth/register`

Create a new user account.

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "securepassword123",
  "name": "John Doe",
  "phone": "+1234567890"
}
```

**Response (201):**

```json
{
  "success": true,
  "message": "User registered successfully",
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "name": "John Doe",
    "phone": "+1234567890",
    "email_verified": false,
    "phone_verified": false,
    "created_at": "2024-01-01T00:00:00Z"
  }
}
```

**Response (400):**

```json
{
  "success": false,
  "error": "Email already exists",
  "code": "EMAIL_EXISTS"
}
```

### Login User

**POST** `/api/auth/login`

Authenticate user and receive access tokens.

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "Login successful",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 86400,
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "name": "John Doe",
    "role": "user"
  }
}
```

**Response (401):**

```json
{
  "success": false,
  "error": "Invalid credentials",
  "code": "INVALID_CREDENTIALS"
}
```

### Logout User

**POST** `/api/auth/logout`

Logout user and invalidate tokens.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200):**

```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

### Refresh Token

**POST** `/api/auth/refresh`

Refresh access token using refresh token.

**Request Body:**

```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200):**

```json
{
  "success": true,
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 86400
}
```

## Password Management

### Forgot Password

**POST** `/api/auth/forgot-password`

Send password reset email.

**Request Body:**

```json
{
  "email": "user@example.com"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "Password reset email sent"
}
```

### Reset Password

**POST** `/api/auth/reset-password`

Reset password using reset token.

**Request Body:**

```json
{
  "token": "reset-token-here",
  "password": "newpassword123"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "Password reset successfully"
}
```

### Change Password

**PUT** `/api/auth/change-password`

Change password for authenticated user.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Request Body:**

```json
{
  "current_password": "oldpassword123",
  "new_password": "newpassword123"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "Password changed successfully"
}
```

## Email Verification

### Send Verification Email

**POST** `/api/auth/send-verification-email`

Send email verification link.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200):**

```json
{
  "success": true,
  "message": "Verification email sent"
}
```

### Verify Email

**GET** `/api/auth/verify-email`

Verify email using verification token. This endpoint is meant to be accessed directly from the email link sent to the user.

**Query Parameters:**

```
?token=verification-token-here
```

**Response (302 Redirect):**

Redirects to the frontend verify email page with status and message query parameters:

```
Location: http://your-frontend.com/verify-email?status=success&message=Email%20verified%20successfully
```

Or on error:

```
Location: http://your-frontend.com/verify-email?status=error&message=Error%20message
```

**Note:** If `FrontendConfig` is not set, it falls back to a JSON response:

```json
{
  "success": true,
  "message": "Email verified successfully"
}
```

## Phone Verification

### Send Phone Verification

**POST** `/api/auth/send-phone-verification`

Send SMS verification code.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Request Body:**

```json
{
  "phone": "+1234567890"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "Verification code sent"
}
```

### Verify Phone

**POST** `/api/auth/verify-phone`

Verify phone using verification code.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Request Body:**

```json
{
  "phone": "+1234567890",
  "code": "123456"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "Phone verified successfully"
}
```

## OAuth Authentication

### Initiate OAuth

**GET** `/api/auth/oauth/{provider}`

Start OAuth flow for specified provider.

**Path Parameters:**

- `provider`: OAuth provider (google, github, facebook, etc.)

**Query Parameters:**

```
?redirect_uri=https://yourdomain.com/callback
&state=random-state-string
```

**Response (302):**
Redirects to OAuth provider.

### OAuth Callback

**GET** `/api/auth/oauth/{provider}/callback`

Handle OAuth callback from provider.

**Path Parameters:**

- `provider`: OAuth provider

**Query Parameters:**

```
?code=authorization-code
&state=state-string
```

**Response (200):**

```json
{
  "success": true,
  "message": "OAuth authentication successful",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "name": "John Doe"
  }
}
```

### Link OAuth Account

**POST** `/api/auth/oauth/{provider}/link`

Link OAuth account to existing user.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Path Parameters:**

- `provider`: OAuth provider

**Request Body:**

```json
{
  "code": "authorization-code",
  "state": "state-string"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "OAuth account linked successfully"
}
```

### Unlink OAuth Account

**DELETE** `/api/auth/oauth/{provider}/unlink`

Unlink OAuth account from user.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Path Parameters:**

- `provider`: OAuth provider

**Response (200):**

```json
{
  "success": true,
  "message": "OAuth account unlinked successfully"
}
```

## Two-Factor Authentication

### Enable 2FA

**POST** `/api/auth/2fa/enable`

Enable two-factor authentication.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Request Body:**

```json
{
  "method": "totp"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "2FA enabled successfully",
  "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
  "secret": "JBSWY3DPEHPK3PXP"
}
```

### Verify 2FA

**POST** `/api/auth/2fa/verify`

Verify 2FA code during login.

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "password123",
  "code": "123456"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "2FA verification successful",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "user-uuid",
    "email": "user@example.com"
  }
}
```

### Disable 2FA

**POST** `/api/auth/2fa/disable`

Disable two-factor authentication.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Request Body:**

```json
{
  "code": "123456"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "2FA disabled successfully"
}
```

## User Management

### Get User Profile

**GET** `/api/auth/me`

Get current user's profile information.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200):**

```json
{
  "success": true,
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "name": "John Doe",
    "phone": "+1234567890",
    "email_verified": true,
    "phone_verified": false,
    "two_factor_enabled": true,
    "role": "user",
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

### Update User Profile

**PUT** `/api/auth/profile`

Update user profile information.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Request Body:**

```json
{
  "name": "John Smith",
  "phone": "+1234567890"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "Profile updated successfully",
  "user": {
    "id": "user-uuid",
    "name": "John Smith",
    "phone": "+1234567890",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

### Deactivate Account

**DELETE** `/api/auth/account`

Deactivate user account.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Request Body:**

```json
{
  "password": "password123"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "Account deactivated successfully"
}
```

## Session Management

### Get User Sessions

**GET** `/api/auth/sessions`

Get all active sessions for current user.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200):**

```json
{
  "success": true,
  "sessions": [
    {
      "id": "session-uuid",
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0...",
      "created_at": "2024-01-01T00:00:00Z",
      "last_used": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### Revoke Session

**DELETE** `/api/auth/sessions/{session_id}`

Revoke specific session.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Path Parameters:**

- `session_id`: Session UUID

**Response (200):**

```json
{
  "success": true,
  "message": "Session revoked successfully"
}
```

### Revoke All Sessions

**DELETE** `/api/auth/sessions`

Revoke all sessions except current one.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200):**

```json
{
  "success": true,
  "message": "All sessions revoked successfully"
}
```

## Admin Endpoints

### Get All Users

**GET** `/api/auth/admin/users`

Get list of all users (admin only).

**Headers:**

```
Authorization: Bearer <admin_access_token>
```

**Query Parameters:**

```
?page=1&limit=20&search=john&role=user
```

**Response (200):**

```json
{
  "success": true,
  "users": [
    {
      "id": "user-uuid",
      "email": "user@example.com",
      "name": "John Doe",
      "role": "user",
      "status": "active",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "pages": 5
  }
}
```

### Update User Role

**PUT** `/api/auth/admin/users/{user_id}/role`

Update user role (admin only).

**Headers:**

```
Authorization: Bearer <admin_access_token>
```

**Path Parameters:**

- `user_id`: User UUID

**Request Body:**

```json
{
  "role": "admin"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "User role updated successfully",
  "user": {
    "id": "user-uuid",
    "role": "admin",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

### Lock/Unlock User

**POST** `/api/auth/admin/users/{user_id}/lock`

Lock or unlock user account (admin only).

**Headers:**

```
Authorization: Bearer <admin_access_token>
```

**Path Parameters:**

- `user_id`: User UUID

**Request Body:**

```json
{
  "locked": true,
  "reason": "Suspicious activity detected"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "User account locked successfully"
}
```

## Health and Status

### Health Check

**GET** `/api/auth/health`

Check API health status.

**Response (200):**

```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z",
  "version": "1.0.0",
  "services": {
    "database": "healthy",
    "cache": "healthy",
    "email": "healthy",
    "sms": "healthy"
  }
}
```

### API Status

**GET** `/api/auth/status`

Get detailed API status information.

**Response (200):**

```json
{
  "status": "operational",
  "uptime": "99.9%",
  "response_time": "45ms",
  "active_users": 1250,
  "total_requests": 1500000,
  "error_rate": "0.1%"
}
```

## Error Responses

### Standard Error Format

All error responses follow this format:

```json
{
  "success": false,
  "error": "Error message description",
  "code": "ERROR_CODE",
  "details": {
    "field": "Additional error details"
  },
  "timestamp": "2024-01-01T00:00:00Z",
  "request_id": "req-uuid-here"
}
```

### Common Error Codes

| Code                       | Description                      | HTTP Status |
| -------------------------- | -------------------------------- | ----------- |
| `INVALID_CREDENTIALS`      | Invalid email/password           | 401         |
| `TOKEN_EXPIRED`            | Access token has expired         | 401         |
| `INVALID_TOKEN`            | Invalid or malformed token       | 401         |
| `INSUFFICIENT_PERMISSIONS` | User lacks required permissions  | 403         |
| `ACCOUNT_LOCKED`           | User account is locked           | 423         |
| `EMAIL_EXISTS`             | Email address already registered | 400         |
| `PHONE_EXISTS`             | Phone number already registered  | 400         |
| `INVALID_2FA_CODE`         | Invalid 2FA verification code    | 400         |
| `RATE_LIMIT_EXCEEDED`      | Too many requests                | 429         |
| `VALIDATION_ERROR`         | Request validation failed        | 400         |

## Rate Limiting

### Rate Limit Headers

Rate-limited endpoints include these headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
X-RateLimit-Reset-Time: Mon, 01 Jan 2024 00:00:00 GMT
```

### Rate Limit Response

When rate limit is exceeded:

**Response (429):**

```json
{
  "success": false,
  "error": "Rate limit exceeded",
  "code": "RATE_LIMIT_EXCEEDED",
  "retry_after": 60
}
```

## Pagination

### Pagination Headers

Paginated endpoints include these headers:

```
X-Pagination-Page: 1
X-Pagination-Limit: 20
X-Pagination-Total: 100
X-Pagination-Pages: 5
```

### Pagination Query Parameters

```
?page=1&limit=20&sort=created_at&order=desc
```

## Filtering and Search

### Search Query Parameters

```
?search=john&role=user&status=active&created_after=2024-01-01
```

### Sort Query Parameters

```
?sort=created_at&order=desc
?sort=name&order=asc
```

## Response Headers

### Standard Headers

All responses include these headers:

```
Content-Type: application/json
X-Request-ID: req-uuid-here
X-Response-Time: 45ms
```

### Security Headers

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

## WebSocket Endpoints

### Real-time Updates

**WebSocket** `/api/auth/ws`

Connect to real-time updates for authenticated users.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Message Types:**

- `user.updated`: User profile updated
- `session.revoked`: Session revoked
- `2fa.enabled`: 2FA enabled
- `2fa.disabled`: 2FA disabled

## Testing Endpoints

### Test Authentication

**POST** `/api/auth/test`

Test endpoint for development/testing.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response (200):**

```json
{
  "success": true,
  "message": "Authentication test successful",
  "user_id": "user-uuid",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## SDK Endpoints

### Get SDK Configuration

**GET** `/api/auth/sdk/config`

Get configuration for client SDKs.

**Response (200):**

```json
{
  "success": true,
  "config": {
    "oauth_providers": ["google", "github", "facebook"],
    "features": {
      "two_factor": true,
      "email_verification": true,
      "phone_verification": true
    },
    "endpoints": {
      "login": "/api/auth/login",
      "register": "/api/auth/register",
      "oauth": "/api/auth/oauth"
    }
  }
}
```

## Next Steps

- [Request/Response Models](models.md) - Learn about data models
- [Authentication](auth.md) - Understand authentication flows
- [Error Handling](errors.md) - Handle errors properly
- [SDK Integration](../frameworks/gin.md) - Integrate with frameworks
