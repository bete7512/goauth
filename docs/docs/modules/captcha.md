---
id: captcha
title: Captcha Module
sidebar_label: Captcha
sidebar_position: 9
---

# Captcha Module

Bot protection via Google reCAPTCHA v3 or Cloudflare Turnstile. Applied as middleware to specific routes — no HTTP endpoints.

## Registration

### Google reCAPTCHA v3

```go
import "github.com/bete7512/goauth/internal/modules/captcha"

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
    Provider       types.CaptchaProvider  // "google" or "cloudflare"
    SiteKey        string                // Public key for frontend widget
    SecretKey      string                // Server-side verification key
    ScoreThreshold float64              // reCAPTCHA v3: 0.0–1.0 (default: 0.5)
    VerifyTimeout  time.Duration        // API timeout (default: 10s)
    HeaderName     string               // Token header (default: "X-Captcha-Token")
    FormFieldName  string               // Form field fallback (default: "captcha_token")
    ApplyToRoutes  []types.RouteName    // Required: routes to protect
    ExcludeRoutes  []types.RouteName    // Routes to exclude
}
```

## Client-Side

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

| Score | Meaning |
|-------|---------|
| 0.0 | Most lenient |
| 0.3 | Recommended for most apps |
| 0.5 | Balanced (default) |
| 0.7 | Strict |
| 1.0 | Most strict |
