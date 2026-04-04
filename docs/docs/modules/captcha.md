---
id: captcha
title: Captcha Module
sidebar_label: Captcha
sidebar_position: 9
---

# Captcha Module

The Captcha module provides bot protection for your authentication endpoints using Google reCAPTCHA v3 or Cloudflare Turnstile. It operates as pure middleware — no HTTP endpoints are exposed. You specify which routes require captcha verification, and the middleware transparently validates the captcha token on each request before the handler runs.

## Capabilities

- **Google reCAPTCHA v3** — Score-based bot detection. Requests receive a score from 0.0 (likely bot) to 1.0 (likely human). Configure `ScoreThreshold` to set your tolerance level (default: 0.5).
- **Cloudflare Turnstile** — Privacy-friendly alternative to reCAPTCHA. Binary pass/fail verification with no score threshold.
- **Per-Route Application** — Apply captcha to specific routes using route names (e.g., `"core.signup"`, `"core.login"`, `"core.forgot_password"`). Not a global middleware — only routes you specify are protected.
- **Route Exclusion** — Use `ExcludeRoutes` to exempt specific routes from captcha even if they match a broader pattern.
- **Configurable Token Source** — Reads the captcha token from an HTTP header (default: `X-Captcha-Token`) or form field (default: `captcha_token`). Supports both API and form-based clients.
- **Configurable Timeout** — Set `VerifyTimeout` for the HTTP call to the provider's verification API (default: 10 seconds).
- **Zero Storage** — Purely stateless. No database or storage required.

## Registration

### Google reCAPTCHA v3

```go
import (
    "github.com/bete7512/goauth/pkg/modules/captcha"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/types"
)

a.Use(captcha.New(&config.CaptchaModuleConfig{
    Provider:       types.CaptchaProviderGoogle,
    SiteKey:        "your-recaptcha-site-key",
    SecretKey:      "your-recaptcha-secret-key",
    ScoreThreshold: 0.5,
    ApplyToRoutes:  []types.RouteName{"core.signup", "core.login"},
}))
```

### Cloudflare Turnstile

```go
a.Use(captcha.New(&config.CaptchaModuleConfig{
    Provider:      types.CaptchaProviderCloudflare,
    SiteKey:       "your-turnstile-site-key",
    SecretKey:     "your-turnstile-secret-key",
    ApplyToRoutes: []types.RouteName{"core.signup", "core.login"},
}))
```

## Configuration

```go
type CaptchaModuleConfig struct {
    // Provider: types.CaptchaProviderGoogle or types.CaptchaProviderCloudflare
    Provider       types.CaptchaProvider

    // Public key for frontend widget
    SiteKey        string

    // Server-side verification key
    SecretKey      string

    // reCAPTCHA v3 minimum score: 0.0-1.0 (default: 0.5)
    // Ignored for Cloudflare Turnstile (binary pass/fail)
    ScoreThreshold float64

    // HTTP timeout for provider API calls (default: 10s)
    VerifyTimeout  time.Duration

    // HTTP header to read the captcha token from (default: "X-Captcha-Token")
    HeaderName     string

    // Form field fallback for the captcha token (default: "captcha_token")
    FormFieldName  string

    // Required: route names or patterns that require captcha
    ApplyToRoutes  []types.RouteName

    // Route names or patterns to exclude from captcha
    ExcludeRoutes  []types.RouteName
}
```

## Middleware

The module registers a `captcha` middleware (priority 70) that is applied only to the routes listed in `ApplyToRoutes`. If `Provider` is empty or `ApplyToRoutes` is empty, no middleware is registered.

The middleware extracts the captcha token from the configured header (default `X-Captcha-Token`) or form field (default `captcha_token`), then verifies it against the provider API.

## Client-Side Integration

### reCAPTCHA v3

```html
<script src="https://www.google.com/recaptcha/api.js?render=YOUR_SITE_KEY"></script>
<script>
grecaptcha.ready(function() {
    grecaptcha.execute('YOUR_SITE_KEY', {action: 'login'})
    .then(function(token) {
        fetch('/api/v1/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Captcha-Token': token
            },
            body: JSON.stringify({email: '...', password: '...'})
        });
    });
});
</script>
```

### Cloudflare Turnstile

```html
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<form action="/api/v1/login" method="POST">
    <div class="cf-turnstile" data-sitekey="YOUR_SITE_KEY"></div>
    <!-- form fields -->
    <button type="submit">Login</button>
</form>
```

## Score Threshold (reCAPTCHA v3)

| Score | Meaning            |
|-------|--------------------|
| 0.0   | Most lenient       |
| 0.3   | Recommended for most apps |
| 0.5   | Balanced (default) |
| 0.7   | Strict             |
| 1.0   | Most strict        |

## Dependencies

None. The Captcha module has no module dependencies and requires no storage.

## Common Route Names

Use these route names in `ApplyToRoutes` to protect specific endpoints:

| Route Name | Endpoint |
|------------|----------|
| `core.signup` | `POST /signup` |
| `core.login` | `POST /login` |
| `core.forgot_password` | `POST /forgot-password` |
| `core.reset_password` | `POST /reset-password` |
| `magic_link.send` | `POST /magic-link/send` |
