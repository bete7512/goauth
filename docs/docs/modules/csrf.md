---
id: csrf
title: CSRF Module
sidebar_label: CSRF
sidebar_position: 10
---

# CSRF Module

Token-based CSRF protection using the HMAC-based double-submit cookie pattern. Tokens are stateless — no server-side storage needed.

## Registration

```go
import "github.com/bete7512/goauth/internal/modules/csrf"

a.Use(csrf.New(&config.CSRFModuleConfig{
    TokenExpiry:      1 * time.Hour,
    CookieName:       "__goauth_csrf",
    HeaderName:       "X-CSRF-Token",
    FormFieldName:    "csrf_token",
    Secure:           true,
    SameSite:         http.SameSiteLaxMode,
    ExcludePaths:     []string{"/api/v1/csrf-token"},
    ProtectedMethods: []string{"POST", "PUT", "DELETE", "PATCH"},
}))
```

## Configuration

```go
type CSRFModuleConfig struct {
    TokenExpiry      time.Duration  // Token validity (default: 1 hour)
    CookieName       string         // Cookie name (default: "__goauth_csrf")
    HeaderName       string         // Header for token (default: "X-CSRF-Token")
    FormFieldName    string         // Form field name (default: "csrf_token")
    Secure           bool           // Secure cookie flag (default: true)
    SameSite         http.SameSite  // SameSite attribute (default: Lax)
    CookiePath       string         // Cookie path (default: "/")
    CookieDomain     string         // Cookie domain
    ExcludePaths     []string       // Paths that skip CSRF validation
    ProtectedMethods []string       // Methods that require CSRF (default: POST, PUT, DELETE, PATCH)
}
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/csrf-token` | Get a CSRF token (also sets cookie) |

## Client-Side Usage

### 1. Get the token

```javascript
const res = await fetch('/api/v1/csrf-token');
const data = await res.json();
const csrfToken = data.csrf_token;
```

### 2. Include in requests

**Header** (recommended):
```javascript
fetch('/api/v1/signup', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify({...})
});
```

**Form field**:
```html
<form method="POST" action="/api/v1/signup">
    <input type="hidden" name="csrf_token" value="...">
    <!-- other fields -->
</form>
```
