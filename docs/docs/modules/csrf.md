---
id: csrf
title: CSRF Module
sidebar_label: CSRF
sidebar_position: 10
---

# CSRF Module

The CSRF module provides stateless cross-site request forgery protection using the HMAC-based double-submit cookie pattern. No server-side storage is required — tokens are cryptographically generated and validated using HMAC with the JWT secret key. It works automatically as global middleware on all state-changing HTTP methods.

## Capabilities

- **Double-Submit Cookie Pattern** — The server issues both a CSRF cookie and a CSRF token. On state-changing requests, the client must send the token back via header or form field. The server validates the token's HMAC signature against the cookie.
- **Stateless** — No server-side token storage. Tokens are self-validating via HMAC, making this compatible with horizontally scaled deployments.
- **Configurable Token Expiry** — Tokens expire after a configurable duration (default: 1 hour).
- **SameSite Cookie Support** — Configure the `SameSite` attribute on the CSRF cookie (default: `Lax`). Use `Strict` for maximum security or `None` for cross-origin scenarios.
- **Secure Cookie Flag** — CSRF cookie marked as `Secure` by default, ensuring it is only sent over HTTPS.
- **Path and Domain Scoping** — Configure `CookiePath` and `CookieDomain` to scope the CSRF cookie to specific paths or subdomains.
- **Excluded Paths** — Skip CSRF validation for specific paths (e.g., webhooks, API endpoints authenticated via other means). Useful for paths like the CSRF token endpoint itself.
- **Configurable Protected Methods** — By default, `POST`, `PUT`, `DELETE`, and `PATCH` require CSRF validation. `GET`, `HEAD`, and `OPTIONS` are always exempt.
- **Multiple Token Sources** — Reads the token from HTTP header (default: `X-CSRF-Token`) or form field (default: `csrf_token`), supporting both SPA and traditional form clients.
- **Zero Storage** — Purely stateless. No database or storage required.

## Registration

```go
import (
    "net/http"
    "time"

    "github.com/bete7512/goauth/pkg/modules/csrf"
    "github.com/bete7512/goauth/pkg/config"
)

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

// Or with defaults
a.Use(csrf.New(nil))
```

## Configuration

```go
type CSRFModuleConfig struct {
    // Token validity (default: 1 hour)
    TokenExpiry      time.Duration

    // Cookie name (default: "__goauth_csrf")
    CookieName       string

    // HTTP header clients send the token in (default: "X-CSRF-Token")
    HeaderName       string

    // Form field name for the token (default: "csrf_token")
    FormFieldName    string

    // Secure flag on the CSRF cookie (default: true)
    Secure           bool

    // SameSite attribute on the CSRF cookie (default: Lax)
    SameSite         http.SameSite

    // Path attribute on the CSRF cookie (default: "/")
    CookiePath       string

    // Domain attribute on the CSRF cookie (default: "")
    CookieDomain     string

    // URL path prefixes that skip CSRF validation
    ExcludePaths     []string

    // HTTP methods that require CSRF validation (default: POST, PUT, DELETE, PATCH)
    ProtectedMethods []string
}
```

## Endpoint

| Method | Path           | Auth | Description                            |
|--------|----------------|------|----------------------------------------|
| GET    | `/csrf-token`  | No   | Get a CSRF token (also sets the cookie)|

Route name: `csrf.token`.

## Middleware

The module registers a global `csrf.protect` middleware (priority 85). It validates the CSRF token on all protected methods (POST, PUT, DELETE, PATCH by default) except paths listed in `ExcludePaths`.

The middleware checks for the token in this order:
1. HTTP header (`X-CSRF-Token` by default)
2. Form field (`csrf_token` by default)

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

## Dependencies

None. The CSRF module has no module dependencies and requires no storage. It uses the `JwtSecretKey` from `SecurityConfig` for HMAC signing.
