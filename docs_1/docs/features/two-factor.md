---
id: two-factor
title: Two-Factor Authentication
sidebar_label: Two-Factor Authentication
sidebar_position: 3
---

# Two-Factor Authentication

GoAuth provides robust two-factor authentication (2FA) support with multiple methods including TOTP, SMS, and email verification.

## Overview

Two-factor authentication adds an extra layer of security by requiring users to provide a second form of verification in addition to their password. GoAuth supports multiple 2FA methods and provides a flexible implementation.

## Supported 2FA Methods

### 1. TOTP (Time-based One-Time Password)

- Google Authenticator
- Authy
- Microsoft Authenticator
- Any TOTP-compatible app

### 2. SMS Verification

- Twilio
- AWS SNS
- Custom SMS providers

### 3. Email Verification

- SMTP providers
- Custom email services

## TOTP Implementation

### Setup TOTP for User

```go
// Enable 2FA for user
func enable2FA(c *gin.Context) {
    user := auth.GetUser(c)

    // Generate secret key
    secret, err := generateTOTPSecret()
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to generate secret"})
        return
    }

    // Generate QR code URL
    qrURL := generateTOTPQRCode(user.Email, secret)

    // Store secret temporarily (encrypted)
    tempSecret := encryptSecret(secret)
    session.Set("temp_2fa_secret", tempSecret)

    c.JSON(200, gin.H{
        "secret": secret,
        "qr_url": qrURL,
        "message": "Scan QR code with your authenticator app",
    })
}

// Verify and enable 2FA
func verifyAndEnable2FA(c *gin.Context) {
    user := auth.GetUser(c)

    var req struct {
        Code string `json:"code" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // Get temporary secret from session
    tempSecret := session.Get("temp_2fa_secret")
    if tempSecret == nil {
        c.JSON(400, gin.H{"error": "2FA setup session expired"})
        return
    }

    secret := decryptSecret(tempSecret.(string))

    // Verify TOTP code
    if !verifyTOTPCode(secret, req.Code) {
        c.JSON(400, gin.H{"error": "Invalid 2FA code"})
        return
    }

    // Enable 2FA for user
    err := auth.Enable2FA(user.ID, secret, "totp")
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to enable 2FA"})
        return
    }

    // Clear temporary secret
    session.Delete("temp_2fa_secret")

    c.JSON(200, gin.H{
        "message": "2FA enabled successfully",
    })
}
```

### TOTP Code Generation

```go
import (
    "github.com/pquerna/otp/totp"
    "github.com/pquerna/otp"
)

// Generate TOTP secret
func generateTOTPSecret() (string, error) {
    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      "GoAuth",
        AccountName: "user@example.com",
    })
    if err != nil {
        return "", err
    }

    return key.Secret(), nil
}

// Generate QR code URL
func generateTOTPQRCode(email, secret string) string {
    key := &otp.Key{
        Type:     otp.TypeTotp,
        Issuer:   "GoAuth",
        Account:  email,
        Secret:   secret,
        Algorithm: otp.AlgorithmSHA1,
        Digits:   6,
        Period:   30,
    }

    return key.URL()
}

// Verify TOTP code
func verifyTOTPCode(secret, code string) bool {
    return totp.Validate(code, secret)
}
```

## SMS 2FA Implementation

### Setup SMS 2FA

```go
// Enable SMS 2FA
func enableSMS2FA(c *gin.Context) {
    user := auth.GetUser(c)

    // Generate verification code
    code := generateVerificationCode()

    // Store code temporarily
    session.Set("sms_verification_code", code)
    session.Set("sms_verification_time", time.Now())

    // Send SMS
    err := sendSMS(user.Phone, fmt.Sprintf("Your 2FA code is: %s", code))
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to send SMS"})
        return
    }

    c.JSON(200, gin.H{
        "message": "SMS verification code sent",
    })
}

// Verify SMS code and enable 2FA
func verifySMS2FA(c *gin.Context) {
    user := auth.GetUser(c)

    var req struct {
        Code string `json:"code" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // Get stored verification code
    storedCode := session.Get("sms_verification_code")
    storedTime := session.Get("sms_verification_time")

    if storedCode == nil || storedTime == nil {
        c.JSON(400, gin.H{"error": "SMS verification session expired"})
        return
    }

    // Check if code is expired (5 minutes)
    if time.Since(storedTime.(time.Time)) > 5*time.Minute {
        session.Delete("sms_verification_code")
        session.Delete("sms_verification_time")
        c.JSON(400, gin.H{"error": "SMS code expired"})
        return
    }

    // Verify code
    if storedCode.(string) != req.Code {
        c.JSON(400, gin.H{"error": "Invalid SMS code"})
        return
    }

    // Enable SMS 2FA
    err := auth.Enable2FA(user.ID, "", "sms")
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to enable 2FA"})
        return
    }

    // Clear session data
    session.Delete("sms_verification_code")
    session.Delete("sms_verification_time")

    c.JSON(200, gin.H{
        "message": "SMS 2FA enabled successfully",
    })
}
```

## Email 2FA Implementation

### Setup Email 2FA

```go
// Enable email 2FA
func enableEmail2FA(c *gin.Context) {
    user := auth.GetUser(c)

    // Generate verification code
    code := generateVerificationCode()

    // Store code temporarily
    session.Set("email_verification_code", code)
    session.Set("email_verification_time", time.Now())

    // Send email
    err := sendVerificationEmail(user.Email, code)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to send email"})
        return
    }

    c.JSON(200, gin.H{
        "message": "Email verification code sent",
    })
}

// Verify email code and enable 2FA
func verifyEmail2FA(c *gin.Context) {
    user := auth.GetUser(c)

    var req struct {
        Code string `json:"code" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // Get stored verification code
    storedCode := session.Get("email_verification_code")
    storedTime := session.Get("email_verification_time")

    if storedCode == nil || storedTime == nil {
        c.JSON(400, gin.H{"error": "Email verification session expired"})
        return
    }

    // Check if code is expired (10 minutes)
    if time.Since(storedTime.(time.Time)) > 10*time.Minute {
        session.Delete("email_verification_code")
        session.Delete("email_verification_time")
        c.JSON(400, gin.H{"error": "Email code expired"})
        return
    }

    // Verify code
    if storedCode.(string) != req.Code {
        c.JSON(400, gin.H{"error": "Invalid email code"})
        return
    }

    // Enable email 2FA
    err := auth.Enable2FA(user.ID, "", "email")
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to enable 2FA"})
        return
    }

    // Clear session data
    session.Delete("email_verification_code")
    session.Delete("email_verification_time")

    c.JSON(200, gin.H{
        "message": "Email 2FA enabled successfully",
    })
}
```

## 2FA Authentication Flow

### Login with 2FA

```go
// Login with 2FA
func loginWith2FA(c *gin.Context) {
    var req struct {
        Email    string `json:"email" binding:"required,email"`
        Password string `json:"password" binding:"required"`
        Code     string `json:"code,omitempty"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // First, verify email and password
    user, err := auth.ValidateCredentials(req.Email, req.Password)
    if err != nil {
        c.JSON(401, gin.H{"error": "Invalid credentials"})
        return
    }

    // Check if 2FA is enabled
    if !user.TwoFactorEnabled {
        // 2FA not enabled, proceed with normal login
        result, err := auth.Login(c, req.Email, req.Password)
        if err != nil {
            c.JSON(401, gin.H{"error": err.Error()})
            return
        }

        c.JSON(200, gin.H{
            "access_token": result.AccessToken,
            "refresh_token": result.RefreshToken,
            "user": result.User,
        })
        return
    }

    // 2FA is enabled, verify code
    if req.Code == "" {
        c.JSON(200, gin.H{
            "requires_2fa": true,
            "message": "2FA code required",
        })
        return
    }

    // Verify 2FA code
    if !verify2FACode(user, req.Code) {
        c.JSON(401, gin.H{"error": "Invalid 2FA code"})
        return
    }

    // Generate tokens
    result, err := auth.GenerateTokens(user)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to generate tokens"})
        return
    }

    c.JSON(200, gin.H{
        "access_token": result.AccessToken,
        "refresh_token": result.RefreshToken,
        "user": result.User,
    })
}
```

### 2FA Code Verification

```go
// Verify 2FA code
func verify2FACode(user *models.User, code string) bool {
    switch user.TwoFactorMethod {
    case "totp":
        return verifyTOTPCode(user.TwoFactorSecret, code)
    case "sms":
        return verifySMSCode(user.ID, code)
    case "email":
        return verifyEmailCode(user.ID, code)
    default:
        return false
    }
}

// Verify SMS code from database
func verifySMSCode(userID, code string) bool {
    // Implementation depends on your storage method
    // This is a simplified example
    storedCode, err := getStoredSMSCode(userID)
    if err != nil {
        return false
    }

    return storedCode == code
}

// Verify email code from database
func verifyEmailCode(userID, code string) bool {
    // Implementation depends on your storage method
    // This is a simplified example
    storedCode, err := getStoredEmailCode(userID)
    if err != nil {
        return false
    }

    return storedCode == code
}
```

## 2FA Management

### Disable 2FA

```go
// Disable 2FA
func disable2FA(c *gin.Context) {
    user := auth.GetUser(c)

    var req struct {
        Code string `json:"code" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // Verify current 2FA code before disabling
    if !verify2FACode(user, req.Code) {
        c.JSON(400, gin.H{"error": "Invalid 2FA code"})
        return
    }

    // Disable 2FA
    err := auth.Disable2FA(user.ID)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to disable 2FA"})
        return
    }

    c.JSON(200, gin.H{
        "message": "2FA disabled successfully",
    })
}
```

### Change 2FA Method

```go
// Change 2FA method
func change2FAMethod(c *gin.Context) {
    user := auth.GetUser(c)

    var req struct {
        CurrentCode string `json:"current_code" binding:"required"`
        NewMethod   string `json:"new_method" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // Verify current 2FA code
    if !verify2FACode(user, req.CurrentCode) {
        c.JSON(400, gin.H{"error": "Invalid current 2FA code"})
        return
    }

    // Validate new method
    validMethods := []string{"totp", "sms", "email"}
    if !contains(validMethods, req.NewMethod) {
        c.JSON(400, gin.H{"error": "Invalid 2FA method"})
        return
    }

    // Change 2FA method
    err := auth.Change2FAMethod(user.ID, req.NewMethod)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to change 2FA method"})
        return
    }

    c.JSON(200, gin.H{
        "message": "2FA method changed successfully",
        "new_method": req.NewMethod,
    })
}
```

## Backup Codes

### Generate Backup Codes

```go
// Generate backup codes
func generateBackupCodes(c *gin.Context) {
    user := auth.GetUser(c)

    // Generate 10 backup codes
    backupCodes := generateBackupCodesList()

    // Store hashed backup codes
    err := auth.StoreBackupCodes(user.ID, backupCodes)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to generate backup codes"})
        return
    }

    c.JSON(200, gin.H{
        "backup_codes": backupCodes,
        "message": "Store these codes securely. Each can only be used once.",
    })
}

// Generate backup codes list
func generateBackupCodesList() []string {
    codes := make([]string, 10)
    for i := 0; i < 10; i++ {
        codes[i] = generateRandomCode(8)
    }
    return codes
}

// Verify backup code
func verifyBackupCode(userID, code string) bool {
    return auth.VerifyBackupCode(userID, code)
}
```

## Configuration

### 2FA Configuration

```go
cfg := &config.Config{
    Security: config.SecurityConfig{
        TwoFactor: config.TwoFactorConfig{
            Enabled: true,
            Methods: []string{"totp", "sms", "email"},
            TOTP: config.TOTPConfig{
                Algorithm: "SHA1",
                Digits:    6,
                Period:    30,
                Window:    1,
            },
            SMS: config.SMSConfig{
                Provider: "twilio",
                CodeLength: 6,
                Expiration: 5 * time.Minute,
            },
            Email: config.EmailConfig{
                Provider: "smtp",
                CodeLength: 6,
                Expiration: 10 * time.Minute,
            },
        },
    },
}
```

## Security Considerations

### Rate Limiting

```go
// Rate limiting for 2FA endpoints
func rateLimit2FA() gin.HandlerFunc {
    limiter := rate.NewLimiter(rate.Every(1*time.Minute), 3) // 3 attempts per minute

    return func(c *gin.Context) {
        if !limiter.Allow() {
            c.JSON(429, gin.H{"error": "Too many 2FA attempts"})
            c.Abort()
            return
        }
        c.Next()
    }
}

// Apply rate limiting
r.POST("/auth/2fa/verify", rateLimit2FA(), verify2FA)
r.POST("/auth/2fa/enable", rateLimit2FA(), enable2FA)
```

### Account Lockout

```go
// Account lockout after failed 2FA attempts
func check2FAAttempts(c *gin.Context) {
    userID := c.GetString("user_id")

    attempts, err := get2FAAttempts(userID)
    if err != nil {
        c.Next()
        return
    }

    if attempts >= 5 {
        // Lock account for 15 minutes
        lockAccount(userID, 15*time.Minute)
        c.JSON(423, gin.H{"error": "Account locked due to too many failed attempts"})
        c.Abort()
        return
    }

    c.Next()
}
```

## Testing 2FA

### Unit Tests

```go
func TestTOTPGeneration(t *testing.T) {
    secret, err := generateTOTPSecret()
    assert.NoError(t, err)
    assert.NotEmpty(t, secret)

    // Test QR code generation
    qrURL := generateTOTPQRCode("test@example.com", secret)
    assert.Contains(t, qrURL, "otpauth://totp")
}

func TestTOTPVerification(t *testing.T) {
    secret := "JBSWY3DPEHPK3PXP"
    code := "123456"

    // Test invalid code
    assert.False(t, verifyTOTPCode(secret, code))

    // Test valid code (you'll need to generate a real TOTP code)
    // This requires time-based testing
}
```

### Integration Tests

```go
func Test2FALoginFlow(t *testing.T) {
    // Setup test environment
    auth := setupTestAuth(t)

    // Test login without 2FA
    loginResp := performLogin(t, auth, "user@example.com", "password")
    assert.Equal(t, 200, loginResp.Code)

    // Enable 2FA
    enable2FAResp := performEnable2FA(t, auth, "user@example.com")
    assert.Equal(t, 200, enable2FAResp.Code)

    // Test login with 2FA
    login2FAResp := performLoginWith2FA(t, auth, "user@example.com", "password", "123456")
    assert.Equal(t, 200, login2FAResp.Code)
}
```

## Best Practices

### 1. User Experience

- Provide clear instructions for 2FA setup
- Offer multiple 2FA methods
- Include backup codes for account recovery

### 2. Security

- Implement rate limiting for 2FA attempts
- Use secure session management
- Encrypt sensitive 2FA data

### 3. Recovery

- Provide backup codes
- Offer alternative verification methods
- Implement account recovery procedures

## Next Steps

- [Rate Limiting](rate-limiting.md) - Add rate limiting to your 2FA endpoints
- [Security Features](security.md) - Implement advanced security measures
- [Configuration](../configuration/auth.md) - Customize your 2FA setup
- [API Reference](../api/endpoints.md) - Explore the complete API
