# Module Summary

## Available Modules

### 1. Core Module (Always Enabled)
- Basic email/password authentication
- User registration and login
- Session management
- **Routes**: `/signup`, `/login`, `/me`, `/profile`

### 2. Two-Factor Authentication Module
```go
auth.Use(twofactor.New(&twofactor.TwoFactorConfig{
    Issuer:          "MyApp",
    BackupCodesCount: 10,
    CodeLength:      8,
}))
```
- TOTP-based 2FA
- Backup codes
- **Routes**: `/2fa/setup`, `/2fa/verify`, `/2fa/disable`, `/2fa/status`

### 3. Rate Limiter Module
```go
auth.Use(ratelimiter.New(&ratelimiter.RateLimiterConfig{
    RequestsPerMinute: 60,
    RequestsPerHour:   1000,
    BurstSize:         10,
}))
```
- Per-IP rate limiting
- Prevents brute force attacks
- **Global middleware** (applies to all routes)

### 4. Captcha Module
```go
// Google reCAPTCHA v3
auth.Use(captcha.New(&captcha.CaptchaConfig{
    Provider:           "google",
    RecaptchaSiteKey:   "your-site-key",
    RecaptchaSecretKey: "your-secret-key",
    RecaptchaThreshold: 0.5,
    ApplyToRoutes:      []string{"core.login", "core.signup"},
}))

// OR Cloudflare Turnstile
auth.Use(captcha.New(&captcha.CaptchaConfig{
    Provider:           "cloudflare",
    TurnstileSiteKey:   "your-site-key",
    TurnstileSecretKey: "your-secret-key",
    ApplyToRoutes:      []string{"core.login", "core.signup"},
}))
```
- Bot protection
- Google reCAPTCHA v3 or Cloudflare Turnstile
- **Selective middleware** (applies to specified routes)

### 5. CSRF Protection Module
```go
auth.Use(csrf.New(&csrf.CSRFConfig{
    TokenLength:      32,
    TokenExpiry:      3600,
    Secure:           true,
    HTTPOnly:         true,
    SameSite:         http.SameSiteStrictMode,
    ExcludePaths:     []string{"/auth/csrf-token"},
    ProtectedMethods: []string{"POST", "PUT", "DELETE", "PATCH"},
}))
```
- CSRF token validation
- **Route**: `/csrf-token` (get token)
- **Global middleware** (applies to all routes)

---

## Module Types

### Type 1: Feature Modules (with routes, models, handlers)
- Core Module ✓
- Two-Factor Module ✓
- OAuth Module (planned)
- Magic Link Module (planned)
- Admin Module (planned)

### Type 2: Middleware-Only Modules (no routes or models)
- Rate Limiter Module ✓
- Captcha Module ✓
- CSRF Protection Module ✓

---

## Quick Start

```go
package main

import (
    "context"
    "log"

    "github.com/bete7512/goauth/modules/captcha"
    "github.com/bete7512/goauth/modules/csrf"
    "github.com/bete7512/goauth/modules/ratelimiter"
    "github.com/bete7512/goauth/modules/twofactor"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    gormstorage "github.com/bete7512/goauth/pkg/storage/gorm"
)

func main() {
    // 1. Create storage
    storage, _ := gormstorage.New(&storage.StorageConfig{
        Driver: "sqlite",
        DSN:    "auth.db",
    })

    // 2. Create auth instance
    authInstance, _ := auth.New(&config.Config{
        Storage:         storage,
        SecretKey:       "your-secret-key",
        SessionDuration: 24 * time.Hour,
        AutoMigrate:     true,
    })

    // 3. Register modules
    authInstance.Use(twofactor.New(&twofactor.TwoFactorConfig{
        Issuer: "MyApp",
    }))
    
    authInstance.Use(ratelimiter.New(&ratelimiter.RateLimiterConfig{
        RequestsPerMinute: 60,
    }))
    
    authInstance.Use(captcha.New(&captcha.CaptchaConfig{
        Provider:      "google",
        // ... keys ...
        ApplyToRoutes: []string{"core.login", "core.signup"},
    }))
    
    authInstance.Use(csrf.New(&csrf.CSRFConfig{
        Secure: true,
    }))

    // 4. Initialize
    authInstance.Initialize(context.Background())

    // 5. Use routes
    routes := authInstance.Routes()
    // Register routes with your HTTP server
}
```

---

## Environment Variables

```bash
# Required
export AUTH_SECRET_KEY="your-secret-key"
export DATABASE_DSN="sqlite:auth.db"

# Optional: Google reCAPTCHA
export RECAPTCHA_SITE_KEY="your-site-key"
export RECAPTCHA_SECRET_KEY="your-secret-key"

# Optional: Cloudflare Turnstile
export TURNSTILE_SITE_KEY="your-site-key"
export TURNSTILE_SECRET_KEY="your-secret-key"
```
