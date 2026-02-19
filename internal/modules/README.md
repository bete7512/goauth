# Go-Auth Modules

This document describes the modular architecture, available modules, and how to register and use them with the new `auth.New` and `Initialize` flow.

## Table of Contents

1. [Core Module](#core-module)
2. [Two-Factor Authentication](#two-factor-authentication)
3. [Captcha Protection](#captcha-protection)
5. [CSRF Protection](#csrf-protection)
6. [Admin Module](#admin-module)
7. [OAuth Module](#oauth-module)
8. [Magic Link Module](#magic-link-module)

---

## Core Module

The **Core Module** is auto-registered by `auth.New` when storage provides required repositories. It provides basic authentication primitives (users, sessions, tokens) and base routes.

### Features
- User registration (signup)
- User login with email/password
- User profile management
- Session management
- Password hashing with bcrypt

### Routes
- `POST /auth/signup` - Register a new user
- `POST /auth/login` - Login with credentials
- `GET /auth/me` - Get current user (authenticated)
- `GET /auth/profile` - Get user profile (authenticated)

### Example
```go
a, err := auth.New(&config.Config{
    Storage: storage,
    Security: config.SecurityConfig{
        JwtSecretKey:  "your-secret",
        EncryptionKey: "your-encryption",
    },
    AutoMigrate: true,
})
if err != nil { /* handle */ }
// optional modules -> a.Use(...)
_ = a.Initialize(context.Background())
```

---

## Two-Factor Authentication

The **Two-Factor Module** adds TOTP-based two-factor authentication support.

### Features
- TOTP (Time-based One-Time Password) generation
- QR code URL generation for authenticator apps
- Backup codes for account recovery
- Configurable issuer name
- Optional mandatory 2FA for all users

### Configuration
```go
twoFactorConfig := &twofactor.TwoFactorConfig{
    Issuer:          "MyApp",           // Name shown in authenticator app
    Required:        false,              // Make 2FA mandatory
    BackupCodesCount: 10,                // Number of backup codes
    CodeLength:      8,                  // Length of each backup code
}

a.Use(twofactor.New(twoFactorConfig))
```

### Routes
- `POST /auth/2fa/setup` - Initialize 2FA setup
- `POST /auth/2fa/verify` - Verify and enable 2FA
- `POST /auth/2fa/disable` - Disable 2FA
- `GET /auth/2fa/status` - Get 2FA status

### Usage Flow

1. **Setup 2FA**:
```bash
curl -X POST http://localhost:8080/auth/2fa/setup
# Returns: { "secret": "...", "qr_url": "otpauth://...", "message": "..." }
```

2. **Verify with TOTP code**:
```bash
curl -X POST http://localhost:8080/auth/2fa/verify \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```

3. **Check status**:
```bash
curl http://localhost:8080/auth/2fa/status
# Returns: { "enabled": true, "verified": true, "method": "totp" }
```

---

## Captcha Protection

The **Captcha Module** provides bot protection using Google reCAPTCHA v3 or Cloudflare Turnstile.

### Features
- Google reCAPTCHA v3 with score-based verification
- Cloudflare Turnstile support
- Selective application to specific routes
- Multiple token sources (header, form fields)
- Route exclusion support

### Configuration

#### Google reCAPTCHA v3
```go
captchaConfig := &captcha.CaptchaConfig{
    Provider:           "google",
    RecaptchaSiteKey:   "your-recaptcha-site-key",
    RecaptchaSecretKey: "your-recaptcha-secret-key",
    RecaptchaThreshold: 0.5,  // Score threshold (0.0-1.0)
    
    // Apply to specific routes
    ApplyToRoutes: []string{"core.login", "core.signup"},
    
    // Optionally exclude routes
    ExcludeRoutes: []string{"core.me"},
}

a.Use(captcha.New(captchaConfig))
```

#### Cloudflare Turnstile
```go
captchaConfig := &captcha.CaptchaConfig{
    Provider:           "cloudflare",
    TurnstileSiteKey:   "your-turnstile-site-key",
    TurnstileSecretKey: "your-turnstile-secret-key",
    
    // Apply to specific routes
    ApplyToRoutes: []string{"core.login", "core.signup"},
}

auth.Use(captcha.New(captchaConfig))
```

### Client-Side Integration

#### Google reCAPTCHA v3
```html
<!-- Add reCAPTCHA script -->
<script src="https://www.google.com/recaptcha/api.js?render=YOUR_SITE_KEY"></script>

<script>
function submitLoginForm() {
    grecaptcha.ready(function() {
        grecaptcha.execute('YOUR_SITE_KEY', {action: 'login'})
        .then(function(token) {
            // Option 1: Send in header
            fetch('/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Captcha-Token': token
                },
                body: JSON.stringify({
                    email: '...',
                    password: '...'
                })
            });
            
            // Option 2: Send in form
            document.getElementById('captcha-token').value = token;
            document.getElementById('login-form').submit();
        });
    });
}
</script>

<form id="login-form" onsubmit="event.preventDefault(); submitLoginForm();">
    <input type="hidden" name="g-recaptcha-response" id="captcha-token">
    <!-- other form fields -->
</form>
```

#### Cloudflare Turnstile
```html
<!-- Add Turnstile script -->
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>

<form action="/auth/login" method="POST">
    <!-- Turnstile widget (automatic token submission) -->
    <div class="cf-turnstile" data-sitekey="YOUR_SITE_KEY"></div>
    
    <!-- other form fields -->
    <button type="submit">Login</button>
</form>

<!-- Or manual integration -->
<script>
turnstile.render('#captcha-container', {
    sitekey: 'YOUR_SITE_KEY',
    callback: function(token) {
        // Token can be retrieved and sent manually
        console.log('Captcha token:', token);
    },
});
</script>
```

### Score Threshold (reCAPTCHA v3)
- `0.0` - Most lenient (may allow some bots)
- `0.3` - Recommended for most use cases
- `0.5` - Balanced (default)
- `0.7` - Strict (may challenge some humans)
- `1.0` - Most strict

---

## CSRF Protection

The **CSRF Module** provides protection against Cross-Site Request Forgery attacks.

### Features
- Token-based CSRF protection
- Configurable token length and expiry
- Multiple token sources (header, form, cookie)
- Exclude specific paths
- Customizable HTTP methods to protect

### Configuration
```go
csrfConfig := &csrf.CSRFConfig{
    TokenLength:   32,
    TokenExpiry:   3600,  // 1 hour in seconds
    CookieName:    "csrf_token",
    HeaderName:    "X-CSRF-Token",
    FormFieldName: "csrf_token",
    
    // Cookie settings
    Secure:   true,
    HTTPOnly: true,
    SameSite: http.SameSiteStrictMode,
    
    // Exclude these paths from CSRF protection
    ExcludePaths: []string{"/auth/csrf-token"},
    
    // Protect these HTTP methods
    ProtectedMethods: []string{"POST", "PUT", "DELETE", "PATCH"},
}

a.Use(csrf.New(csrfConfig))
```

### Routes
- `GET /auth/csrf-token` - Get a new CSRF token

### Client-Side Usage

1. **Get CSRF token**:
```javascript
fetch('/auth/csrf-token')
  .then(res => res.json())
  .then(data => {
    const csrfToken = data.csrf_token;
    // Token is also set as a cookie automatically
  });
```

2. **Include token in requests**:

**Option 1: Header**
```javascript
fetch('/auth/signup', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify({...})
});
```

**Option 2: Form field**
```html
<form method="POST" action="/auth/signup">
    <input type="hidden" name="csrf_token" value="...">
    <!-- other fields -->
</form>
```

**Option 3: Cookie (automatic)**
```javascript
// If cookie is set, it will be sent automatically
fetch('/auth/signup', {
    method: 'POST',
    credentials: 'include',  // Include cookies
    body: JSON.stringify({...})
});
```

---

## Complete Example

Here's a complete example using all modules together:

```go
package main

import (
    "context"
    "log"
    "net/http"
    "time"

    "github.com/bete7512/goauth/internal/modules/captcha"
    "github.com/bete7512/goauth/internal/modules/csrf"
    "github.com/bete7512/goauth/internal/modules/twofactor"
    "github.com/bete7512/goauth/internal/storage"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
)

func main() {
    // Create storage via factory
    store, err := storage.NewStorage(config.StorageConfig{
        Driver:  "gorm",
        Dialect: "sqlite",
        DSN:     "auth.db",
        LogLevel: "warn",
    })
    if err != nil {
        log.Fatal(err)
    }

    // Create auth instance
    a, err := auth.New(&config.Config{
        Storage:     store,
        AutoMigrate: true,
        Security: config.SecurityConfig{
            JwtSecretKey:  "change-me",
            EncryptionKey: "change-me",
        },
        CORS: &config.CORSConfig{Enabled: true, AllowedOrigins: []string{"*"}},
    })
    if err != nil {
        log.Fatal(err)
    }

    // Register modules

    // 1. Two-Factor Authentication
    a.Use(twofactor.New(&twofactor.TwoFactorConfig{
        Issuer:          "MyAwesomeApp",
        Required:        false,
        BackupCodesCount: 10,
        CodeLength:      8,
    }))

    // 2. Captcha Protection (Cloudflare Turnstile)
    a.Use(captcha.New(&captcha.CaptchaConfig{
        Provider:           "cloudflare",
        TurnstileSiteKey:   "your-turnstile-site-key",
        TurnstileSecretKey: "your-turnstile-secret-key",
        ApplyToRoutes:      []string{"core.login", "core.signup"},
    }))

    // 3. CSRF Protection
    a.Use(csrf.New(&csrf.CSRFConfig{
        TokenLength:      32,
        TokenExpiry:      3600,
        Secure:           false, // Set to true in production with HTTPS
        HTTPOnly:         true,
        SameSite:         http.SameSiteStrictMode,
        ExcludePaths:     []string{"/auth/csrf-token"},
        ProtectedMethods: []string{"POST", "PUT", "DELETE", "PATCH"},
    }))

    // Initialize all modules
    if err := a.Initialize(context.Background()); err != nil {
        log.Fatal(err)
    }

    // Setup HTTP server
    mux := http.NewServeMux()
    
    // Register all auth routes
    for _, route := range a.Routes() {
        mux.Handle(route.Path, http.HandlerFunc(route.Handler))
    }

    // Your custom routes
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Welcome to MyApp!"))
    })

    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

---

## Environment Variables

For production, use environment variables for sensitive configuration:

```bash
export AUTH_SECRET_KEY="your-super-secret-key"
export RECAPTCHA_SITE_KEY="your-recaptcha-site-key"
export RECAPTCHA_SECRET_KEY="your-recaptcha-secret-key"
export TURNSTILE_SITE_KEY="your-turnstile-site-key"
export TURNSTILE_SECRET_KEY="your-turnstile-secret-key"
export DATABASE_DSN="postgresql://user:pass@localhost/authdb"
```

Then in your code:
```go
config := &config.Config{
    SecretKey: os.Getenv("AUTH_SECRET_KEY"),
    // ... other config
}
```

---

## Security Best Practices

1. **Always use HTTPS in production**
2. **Use strong secret keys** (at least 32 random characters)
3. **Enable CSRF protection** for all state-changing operations
4. **Enable captcha** on authentication endpoints
5. **Set secure cookie flags** (Secure, HttpOnly, SameSite)
6. **Keep dependencies updated**
7. **Use environment variables** for sensitive configuration
8. **Enable 2FA** for admin users
9. **Regularly review audit logs**

---

## Module Creation Scripts

Use the provided scripts to create new modules:

```bash
# Create a module with routes
./new_module_with_route.sh mymodule

# Create a module without routes (middleware only)
./new_module_with_no_route.sh mymodule
```

---

## Testing

Each module includes comprehensive tests. Run tests with:

```bash
# Test all modules
go test ./modules/...

# Test specific module
go test ./modules/twofactor/...

# Test with coverage
go test -cover ./modules/...
```

---

## Contributing

When creating new modules, ensure they:

1. Implement the `Module` interface
2. Have unique route names (module.action format)
3. Include comprehensive tests
4. Document all configuration options
5. Follow the repository pattern for data access
6. Use the event system for hooks
7. Register middlewares with appropriate priorities

---

## Support

For issues, questions, or contributions, please visit the GitHub repository.
