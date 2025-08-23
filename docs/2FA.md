# Two-Factor Authentication (2FA) Implementation

This document provides a comprehensive guide to the Two-Factor Authentication (2FA) system implemented in the Go Auth library.

## 🚀 Overview

The 2FA system supports three authentication methods:
- **TOTP (Time-based One-Time Password)** - Authenticator apps like Google Authenticator
- **Email-based 2FA** - Verification codes sent via email
- **SMS-based 2FA** - Verification codes sent via SMS

## 📋 Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
- [Usage Examples](#usage-examples)
- [Security Features](#security-features)
- [Database Schema](#database-schema)
- [Troubleshooting](#troubleshooting)

## ✨ Features

### 🔐 Authentication Methods

| Method | Description | Requirements |
|--------|-------------|--------------|
| **TOTP** | Time-based codes from authenticator apps | No additional setup |
| **Email** | Verification codes sent to user's email | Email must be verified |
| **SMS** | Verification codes sent to user's phone | Phone must be verified |

### 🛡️ Security Features

- **Encrypted TOTP Secrets**: All TOTP secrets are encrypted before storage
- **Backup Codes**: 8 backup codes for account recovery
- **Time-limited Tokens**: Configurable TTL for all verification codes
- **Password Verification**: Required for disabling 2FA
- **Multiple Methods**: Support for multiple 2FA methods per user
- **Rate Limiting**: Built-in protection against brute force attacks

## 📋 Prerequisites

### Required Dependencies

```go
go get github.com/pquerna/otp/totp
```

### Database Tables

Ensure your database has the following tables:
- `totp_secrets` - Stores encrypted TOTP secrets
- `backup_codes` - Stores hashed backup codes
- `tokens` - Stores verification tokens

## ⚙️ Configuration

### Auth Configuration

```go
config := &config.AuthConfig{
    Methods: config.AuthMethodsConfig{
        EnableTwoFactor: true,
        TwoFactorMethod: "totp", // default method
    },
    Tokens: config.TokenConfig{
        TwoFactorTTL: 10 * time.Minute, // verification code expiry
    },
}
```

### Environment Variables

```bash
# Enable 2FA globally
ENABLE_TWO_FACTOR=true

# Default 2FA method
DEFAULT_2FA_METHOD=totp

# Verification code expiry (in minutes)
TWO_FACTOR_TTL=10
```

## 🔌 API Endpoints

### 1. Enable Two-Factor Authentication

**Endpoint:** `POST /api/2fa/enable`

**Request:**
```json
{
    "method": "totp|email|sms"
}
```

**Response:**
```json
{
    "message": "TOTP two-factor authentication setup initiated",
    "method": "totp",
    "qr_code": "otpauth://totp/example.com:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=example.com&algorithm=SHA1&digits=6&period=30",
    "secret": "JBSWY3DPEHPK3PXP",
    "backup_codes": [
        "ABC12345",
        "DEF67890",
        "GHI11111",
        "JKL22222",
        "MNO33333",
        "PQR44444",
        "STU55555",
        "VWX66666"
    ]
}
```

### 2. Verify Two-Factor Setup

**Endpoint:** `POST /api/2fa/verify-setup`

**Request:**
```json
{
    "code": "123456"
}
```

**Response:**
```json
{
    "message": "two-factor authentication enabled successfully"
}
```

### 3. Two-Factor Login

**Endpoint:** `POST /api/2fa/login`

**Request:**
```json
{
    "email": "user@example.com",
    "password": "password",
    "code": "123456",
    "method": "totp|email|sms|backup"
}
```

**Response:**
```json
{
    "message": "login successful",
    "user": {
        "id": "user-id",
        "email": "user@example.com",
        "two_factor_enabled": true
    },
    "tokens": {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "expires_at": "2024-01-01T12:00:00Z"
    }
}
```

### 4. Verify Two-Factor Code

**Endpoint:** `POST /api/2fa/verify`

**Request:**
```json
{
    "code": "123456",
    "method": "totp|email|sms|backup"
}
```

**Response:**
```json
{
    "message": "two-factor verification successful"
}
```

### 5. Resend Two-Factor Code

**Endpoint:** `POST /api/2fa/resend`

**Request:**
```json
{
    "method": "email|sms"
}
```

**Response:**
```json
{
    "message": "two-factor code resent successfully"
}
```

### 6. Get Two-Factor Status

**Endpoint:** `GET /api/2fa/status`

**Response:**
```json
{
    "enabled": true,
    "methods": ["totp", "email", "sms"]
}
```

### 7. Disable Two-Factor Authentication

**Endpoint:** `POST /api/2fa/disable`

**Request:**
```json
{
    "password": "password"
}
```

**Response:**
```json
{
    "message": "two-factor authentication disabled"
}
```

## 💡 Usage Examples

### Frontend Integration

#### 1. Enable TOTP 2FA

```javascript
// Step 1: Enable 2FA
const enableResponse = await fetch('/api/2fa/enable', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ method: 'totp' })
});

const { qr_code, secret, backup_codes } = await enableResponse.json();

// Step 2: Display QR code to user
const qrCodeElement = document.getElementById('qr-code');
qrCodeElement.src = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(qr_code)}`;

// Step 3: Show backup codes to user
console.log('Backup codes:', backup_codes);

// Step 4: Verify setup
const verifyResponse = await fetch('/api/2fa/verify-setup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: userEnteredCode })
});
```

#### 2. Login with 2FA

```javascript
// Step 1: Regular login
const loginResponse = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        email: 'user@example.com',
        password: 'password'
    })
});

// Step 2: If 2FA is enabled, prompt for code
if (loginResponse.status === 401 && loginResponse.headers.get('X-2FA-Required')) {
    const code = prompt('Enter your 2FA code:');
    
    const twoFactorResponse = await fetch('/api/2fa/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            email: 'user@example.com',
            password: 'password',
            code: code,
            method: 'totp' // or 'email', 'sms', 'backup'
        })
    });
}
```

### Backend Integration

#### 1. Service Usage

```go
// Enable 2FA for a user
req := &dto.EnableTwoFactorRequest{
    Method: "totp",
}
response, err := authService.EnableTwoFactor(ctx, userID, req)

// Verify 2FA code
verifyReq := &dto.TwoFactorVerificationRequest{
    Code:   "123456",
    Method: "totp",
}
err = authService.VerifyTwoFactor(ctx, userID, verifyReq)

// Get 2FA status
status, err := authService.GetTwoFactorStatus(ctx, userID)
```

#### 2. Middleware Integration

```go
// Check if 2FA is required during login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    // ... existing login logic ...
    
    if user.TwoFactorEnabled != nil && *user.TwoFactorEnabled {
        w.Header().Set("X-2FA-Required", "true")
        utils.RespondWithError(w, http.StatusUnauthorized, "2FA required", nil)
        return
    }
    
    // ... continue with normal login ...
}
```

## 🛡️ Security Features

### TOTP Implementation

```go
// Generate TOTP secret
secret := make([]byte, 20)
rand.Read(secret)
secretBase32 := base32.StdEncoding.EncodeToString(secret)

// Encrypt before storage
encryptedSecret, err := tokenManager.Encrypt(secretBase32)

// Verify TOTP code
valid := totp.Validate(code, decryptedSecret)
```

### Backup Codes

- **8 backup codes** generated per user
- **Hashed storage** using bcrypt
- **One-time use** - marked as used after verification
- **Secure generation** using crypto/rand

### Token Management

- **Time-limited tokens** for email/SMS verification
- **Automatic cleanup** of expired tokens
- **Rate limiting** to prevent brute force attacks

## 🗄️ Database Schema

### TOTP Secrets Table

```sql
CREATE TABLE totp_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id),
    secret TEXT NOT NULL, -- encrypted TOTP secret
    backup_url TEXT NOT NULL, -- QR code URL
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### Backup Codes Table

```sql
CREATE TABLE backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    code TEXT NOT NULL UNIQUE, -- hashed backup code
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### Users Table Updates

```sql
ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN enabled_two_factor_methods JSONB;
ALTER TABLE users ADD COLUMN default_two_factor_method VARCHAR(10) DEFAULT 'email';
```

## 🔧 Troubleshooting

### Common Issues

#### 1. TOTP Code Not Working

**Problem:** TOTP codes are not being accepted
**Solution:** 
- Check if the secret is properly encrypted/decrypted
- Verify the time synchronization between server and client
- Ensure the issuer and account name in QR code are correct

#### 2. Email/SMS Codes Not Received

**Problem:** Verification codes are not being sent
**Solution:**
- Check email/SMS service configuration
- Verify user's email/phone is verified
- Check rate limiting settings

#### 3. Backup Codes Not Working

**Problem:** Backup codes are being rejected
**Solution:**
- Ensure backup codes are properly hashed before storage
- Check if the code has already been used
- Verify the hashing algorithm matches

### Debug Mode

Enable debug logging to troubleshoot issues:

```go
// Enable debug logging
config.Logger.SetLevel(log.DebugLevel)

// Check 2FA status
status, err := authService.GetTwoFactorStatus(ctx, userID)
if err != nil {
    log.Errorf("Failed to get 2FA status: %v", err)
}
```

### Testing

```bash
# Run 2FA tests
go test ./tests/unit/api/handlers -v -run TestTwoFactor

# Run integration tests
go test ./tests/integration/api -v -run TestTwoFactor
```

## 📚 Additional Resources

- [TOTP RFC 6238](https://tools.ietf.org/html/rfc6238)
- [Google Authenticator](https://github.com/google/google-authenticator)
- [Authy](https://authy.com/)
- [1Password](https://1password.com/)

## 🤝 Contributing

When contributing to the 2FA implementation:

1. Follow the existing code patterns
2. Add comprehensive tests
3. Update documentation
4. Ensure security best practices
5. Test with multiple authenticator apps

## 📄 License

This 2FA implementation is part of the Go Auth library and follows the same license terms. 