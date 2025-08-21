---
id: recaptcha
title: reCAPTCHA Integration
sidebar_label: reCAPTCHA
sidebar_position: 6
---

# reCAPTCHA Integration

GoAuth provides seamless integration with Google reCAPTCHA and Cloudflare Turnstile to protect your authentication endpoints from bots and automated attacks.

## Overview

reCAPTCHA integration helps protect your authentication system from:

- Bot attacks
- Automated form submissions
- Brute force attempts
- Spam registrations
- Account takeover attempts

## Supported reCAPTCHA Services

### 1. Google reCAPTCHA v2

- Checkbox reCAPTCHA
- Invisible reCAPTCHA
- Custom styling and themes

### 2. Google reCAPTCHA v3

- Score-based protection
- No user interaction required
- Adaptive risk analysis

### 3. Cloudflare Turnstile

- Privacy-focused alternative
- Multiple challenge types
- GDPR compliant

## Configuration

### Basic reCAPTCHA Configuration

```go
cfg := &config.Config{
    Security: config.SecurityConfig{
        reCAPTCHA: config.reCAPTCHAConfig{
            Enabled: true,
            Provider: "google", // "google" or "cloudflare"
            Google: config.GooglereCAPTCHAConfig{
                SiteKey:     "your-site-key",
                SecretKey:   "your-secret-key",
                Version:     "v3", // "v2" or "v3"
                Threshold:   0.5,  // For v3, minimum score (0.0 to 1.0)
            },
            Cloudflare: config.CloudflareConfig{
                SiteKey:   "your-turnstile-site-key",
                SecretKey: "your-turnstile-secret-key",
            },
        },
    },
}
```

### Environment Variables

```bash
# Google reCAPTCHA
RECAPTCHA_ENABLED=true
RECAPTCHA_PROVIDER=google
RECAPTCHA_GOOGLE_SITE_KEY=your-site-key
RECAPTCHA_GOOGLE_SECRET_KEY=your-secret-key
RECAPTCHA_GOOGLE_VERSION=v3
RECAPTCHA_GOOGLE_THRESHOLD=0.5

# Cloudflare Turnstile
RECAPTCHA_CLOUDFLARE_SITE_KEY=your-turnstile-site-key
RECAPTCHA_CLOUDFLARE_SECRET_KEY=your-turnstile-secret-key
```

## Google reCAPTCHA Implementation

### 1. reCAPTCHA v2 (Checkbox)

#### Frontend Implementation

```html
<!-- HTML form with reCAPTCHA -->
<form id="loginForm">
  <input type="email" name="email" placeholder="Email" required />
  <input type="password" name="password" placeholder="Password" required />

  <!-- reCAPTCHA widget -->
  <div class="g-recaptcha" data-sitekey="your-site-key"></div>

  <button type="submit">Login</button>
</form>

<!-- Load reCAPTCHA script -->
<script src="https://www.google.com/recaptcha/api.js" async defer></script>

<script>
  document.getElementById("loginForm").addEventListener("submit", function (e) {
    e.preventDefault();

    // Get reCAPTCHA response
    const recaptchaResponse = grecaptcha.getResponse();
    if (!recaptchaResponse) {
      alert("Please complete the reCAPTCHA");
      return;
    }

    // Submit form with reCAPTCHA token
    const formData = new FormData(this);
    formData.append("recaptcha_token", recaptchaResponse);

    fetch("/api/auth/login", {
      method: "POST",
      body: formData,
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          window.location.href = "/dashboard";
        } else {
          alert(data.error);
          grecaptcha.reset();
        }
      });
  });
</script>
```

#### Backend Validation

```go
// reCAPTCHA v2 validation middleware
func reCAPTCHAv2Middleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.PostForm("recaptcha_token")
        if token == "" {
            c.JSON(400, gin.H{"error": "reCAPTCHA token required"})
            c.Abort()
            return
        }

        // Validate reCAPTCHA token
        if !validateGoogleReCAPTCHAv2(token, c.ClientIP()) {
            c.JSON(400, gin.H{"error": "reCAPTCHA validation failed"})
            c.Abort()
            return
        }

        c.Next()
    }
}

// Validate Google reCAPTCHA v2
func validateGoogleReCAPTCHAv2(token, remoteIP string) bool {
    url := "https://www.google.com/recaptcha/api/siteverify"

    data := url.Values{}
    data.Set("secret", recaptchaSecretKey)
    data.Set("response", token)
    data.Set("remoteip", remoteIP)

    resp, err := http.PostForm(url, data)
    if err != nil {
        log.Printf("reCAPTCHA validation error: %v", err)
        return false
    }
    defer resp.Body.Close()

    var result struct {
        Success     bool    `json:"success"`
        Score       float64 `json:"score"`
        Action      string  `json:"action"`
        ChallengeTS string  `json:"challenge_ts"`
        Hostname    string  `json:"hostname"`
        ErrorCodes  []string `json:"error-codes"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        log.Printf("reCAPTCHA response decode error: %v", err)
        return false
    }

    return result.Success
}
```

### 2. reCAPTCHA v3 (Invisible)

#### Frontend Implementation

```html
<!-- HTML form without visible reCAPTCHA -->
<form id="loginForm">
  <input type="email" name="email" placeholder="Email" required />
  <input type="password" name="password" placeholder="Password" required />
  <button type="submit">Login</button>
</form>

<!-- Load reCAPTCHA v3 script -->
<script src="https://www.google.com/recaptcha/api.js?render=your-site-key"></script>

<script>
  document.getElementById("loginForm").addEventListener("submit", function (e) {
    e.preventDefault();

    // Execute reCAPTCHA with action
    grecaptcha
      .execute("your-site-key", { action: "login" })
      .then(function (token) {
        // Submit form with reCAPTCHA token
        const formData = new FormData(document.getElementById("loginForm"));
        formData.append("recaptcha_token", token);

        fetch("/api/auth/login", {
          method: "POST",
          body: formData,
        })
          .then((response) => response.json())
          .then((data) => {
            if (data.success) {
              window.location.href = "/dashboard";
            } else {
              alert(data.error);
            }
          });
      });
  });
</script>
```

#### Backend Validation

```go
// reCAPTCHA v3 validation middleware
func reCAPTCHAv3Middleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.PostForm("recaptcha_token")
        if token == "" {
            c.JSON(400, gin.H{"error": "reCAPTCHA token required"})
            c.Abort()
            return
        }

        // Validate reCAPTCHA v3 token
        score, action, err := validateGoogleReCAPTCHAv3(token, c.ClientIP())
        if err != nil {
            c.JSON(400, gin.H{"error": "reCAPTCHA validation failed"})
            c.Abort()
            return
        }

        // Check score threshold
        if score < recaptchaThreshold {
            c.JSON(400, gin.H{"error": "reCAPTCHA score too low"})
            c.Abort()
            return
        }

        // Check action
        if action != "login" {
            c.JSON(400, gin.H{"error": "Invalid reCAPTCHA action"})
            c.Abort()
            return
        }

        c.Next()
    }
}

// Validate Google reCAPTCHA v3
func validateGoogleReCAPTCHAv3(token, remoteIP string) (float64, string, error) {
    url := "https://www.google.com/recaptcha/api/siteverify"

    data := url.Values{}
    data.Set("secret", recaptchaSecretKey)
    data.Set("response", token)
    data.Set("remoteip", remoteIP)

    resp, err := http.PostForm(url, data)
    if err != nil {
        return 0, "", err
    }
    defer resp.Body.Close()

    var result struct {
        Success     bool    `json:"success"`
        Score       float64 `json:"score"`
        Action      string  `json:"action"`
        ChallengeTS string  `json:"challenge_ts"`
        Hostname    string  `json:"hostname"`
        ErrorCodes  []string `json:"error-codes"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return 0, "", err
    }

    if !result.Success {
        return 0, "", errors.New("reCAPTCHA validation failed")
    }

    return result.Score, result.Action, nil
}
```

## Cloudflare Turnstile Implementation

### Frontend Implementation

```html
<!-- HTML form with Turnstile -->
<form id="loginForm">
  <input type="email" name="email" placeholder="Email" required />
  <input type="password" name="password" placeholder="Password" required />

  <!-- Turnstile widget -->
  <div class="cf-turnstile" data-sitekey="your-turnstile-site-key"></div>

  <button type="submit">Login</button>
</form>

<!-- Load Turnstile script -->
<script
  src="https://challenges.cloudflare.com/turnstile/v0/api.js"
  async
  defer
></script>

<script>
  document.getElementById("loginForm").addEventListener("submit", function (e) {
    e.preventDefault();

    // Get Turnstile response
    const turnstileResponse = turnstile.getResponse();
    if (!turnstileResponse) {
      alert("Please complete the Turnstile challenge");
      return;
    }

    // Submit form with Turnstile token
    const formData = new FormData(this);
    formData.append("turnstile_token", turnstileResponse);

    fetch("/api/auth/login", {
      method: "POST",
      body: formData,
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          window.location.href = "/dashboard";
        } else {
          alert(data.error);
          turnstile.reset();
        }
      });
  });
</script>
```

### Backend Validation

```go
// Turnstile validation middleware
func turnstileMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.PostForm("turnstile_token")
        if token == "" {
            c.JSON(400, gin.H{"error": "Turnstile token required"})
            c.Abort()
            return
        }

        // Validate Turnstile token
        if !validateCloudflareTurnstile(token, c.ClientIP()) {
            c.JSON(400, gin.H{"error": "Turnstile validation failed"})
            c.Abort()
            return
        }

        c.Next()
    }
}

// Validate Cloudflare Turnstile
func validateCloudflareTurnstile(token, remoteIP string) bool {
    url := "https://challenges.cloudflare.com/turnstile/v0/siteverify"

    data := url.Values{}
    data.Set("secret", turnstileSecretKey)
    data.Set("response", token)
    data.Set("remoteip", remoteIP)

    resp, err := http.PostForm(url, data)
    if err != nil {
        log.Printf("Turnstile validation error: %v", err)
        return false
    }
    defer resp.Body.Close()

    var result struct {
        Success     bool     `json:"success"`
        ChallengeTS string   `json:"challenge_ts"`
        Hostname    string   `json:"hostname"`
        ErrorCodes  []string `json:"error-codes"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        log.Printf("Turnstile response decode error: %v", err)
        return false
    }

    return result.Success
}
```

## Advanced reCAPTCHA Features

### 1. Conditional reCAPTCHA

```go
// Conditional reCAPTCHA based on risk factors
func conditionalReCAPTCHA() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Check if reCAPTCHA is required
        if shouldRequireReCAPTCHA(c) {
            // Apply reCAPTCHA validation
            reCAPTCHAMiddleware()(c)
        } else {
            c.Next()
        }
    }
}

// Determine if reCAPTCHA is required
func shouldRequireReCAPTCHA(c *gin.Context) bool {
    // Check IP reputation
    if isIPHighRisk(c.ClientIP()) {
        return true
    }

    // Check user behavior
    if hasSuspiciousBehavior(c) {
        return true
    }

    // Check time-based factors
    if isHighTrafficPeriod() {
        return true
    }

    return false
}

// Check IP reputation
func isIPHighRisk(ip string) bool {
    // Implement IP reputation checking
    // This could involve checking against blacklists, geolocation, etc.

    // Example: Check if IP is in high-risk countries
    country := getCountryFromIP(ip)
    highRiskCountries := []string{"XX", "YY", "ZZ"}

    for _, riskCountry := range highRiskCountries {
        if country == riskCountry {
            return true
        }
    }

    return false
}
```

### 2. Adaptive reCAPTCHA

```go
// Adaptive reCAPTCHA based on user score
func adaptiveReCAPTCHA() gin.HandlerFunc {
    return func(c *gin.Context) {
        userID := c.GetString("user_id")

        if userID == "" {
            // Anonymous user, always require reCAPTCHA
            reCAPTCHAMiddleware()(c)
            return
        }

        // Get user's trust score
        trustScore := getUserTrustScore(userID)

        if trustScore < 0.7 {
            // Low trust user, require reCAPTCHA
            reCAPTCHAMiddleware()(c)
        } else if trustScore < 0.9 {
            // Medium trust user, require reCAPTCHA v3
            reCAPTCHAv3Middleware()(c)
        } else {
            // High trust user, skip reCAPTCHA
            c.Next()
        }
    }
}

// Calculate user trust score
func getUserTrustScore(userID string) float64 {
    // Implement trust score calculation
    // This could involve factors like:
    // - Account age
    // - Login history
    // - Previous reCAPTCHA scores
    // - Account activity

    score := 0.5 // Base score

    // Account age bonus
    accountAge := getAccountAge(userID)
    if accountAge > 365*24*time.Hour { // 1 year
        score += 0.2
    }

    // Login consistency bonus
    loginConsistency := getLoginConsistency(userID)
    score += loginConsistency * 0.1

    // Previous reCAPTCHA scores
    avgReCAPTCHAScore := getAverageReCAPTCHAScore(userID)
    score += avgReCAPTCHAScore * 0.2

    return math.Min(1.0, score)
}
```

### 3. Multi-Layer reCAPTCHA

```go
// Multi-layer reCAPTCHA for high-risk scenarios
func multiLayerReCAPTCHA() gin.HandlerFunc {
    return func(c *gin.Context) {
        riskLevel := assessRisk(c)

        switch riskLevel {
        case "low":
            // Single reCAPTCHA v3
            reCAPTCHAv3Middleware()(c)
        case "medium":
            // reCAPTCHA v3 + additional verification
            reCAPTCHAv3Middleware()(c)
            if c.IsAborted() {
                return
            }
            additionalVerificationMiddleware()(c)
        case "high":
            // reCAPTCHA v2 + v3 + additional verification
            reCAPTCHAv2Middleware()(c)
            if c.IsAborted() {
                return
            }
            reCAPTCHAv3Middleware()(c)
            if c.IsAborted() {
                return
            }
            additionalVerificationMiddleware()(c)
        }
    }
}

// Assess risk level
func assessRisk(c *gin.Context) string {
    riskScore := 0

    // IP risk
    if isIPHighRisk(c.ClientIP()) {
        riskScore += 3
    }

    // User agent risk
    if isUserAgentSuspicious(c.GetHeader("User-Agent")) {
        riskScore += 2
    }

    // Geographic risk
    if isGeographicHighRisk(c.ClientIP()) {
        riskScore += 2
    }

    // Time-based risk
    if isHighRiskTime() {
        riskScore += 1
    }

    // Determine risk level
    switch {
    case riskScore <= 2:
        return "low"
    case riskScore <= 5:
        return "medium"
    default:
        return "high"
    }
}
```

## reCAPTCHA Analytics and Monitoring

### 1. reCAPTCHA Metrics

```go
// reCAPTCHA metrics tracking
type reCAPTCHAMetrics struct {
    TotalRequests    int64
    SuccessfulValidations int64
    FailedValidations     int64
    AverageScore          float64
    ScoreDistribution     map[string]int
}

// Track reCAPTCHA metrics
func trackReCAPTCHAMetrics(success bool, score float64, action string) {
    metrics := getReCAPTCHAMetrics()

    atomic.AddInt64(&metrics.TotalRequests, 1)

    if success {
        atomic.AddInt64(&metrics.SuccessfulValidations, 1)
    } else {
        atomic.AddInt64(&metrics.FailedValidations, 1)
    }

    // Update average score
    currentAvg := atomic.LoadUint64(&metrics.AverageScore)
    total := atomic.LoadInt64(&metrics.SuccessfulValidations)
    newAvg := (currentAvg + uint64(score*100)) / uint64(total+1)
    atomic.StoreUint64(&metrics.AverageScore, newAvg)

    // Update score distribution
    scoreRange := getScoreRange(score)
    atomic.AddInt64(&metrics.ScoreDistribution[scoreRange], 1)
}

// Get score range for distribution
func getScoreRange(score float64) string {
    switch {
    case score >= 0.9:
        return "0.9-1.0"
    case score >= 0.7:
        return "0.7-0.9"
    case score >= 0.5:
        return "0.5-0.7"
    case score >= 0.3:
        return "0.3-0.5"
    default:
        return "0.0-0.3"
    }
}
```

### 2. reCAPTCHA Monitoring

```go
// Monitor reCAPTCHA performance
func monitorReCAPTCHA() {
    ticker := time.NewTicker(5 * time.Minute)

    for range ticker.C {
        metrics := getReCAPTCHAMetrics()

        // Check success rate
        successRate := float64(metrics.SuccessfulValidations) / float64(metrics.TotalRequests)
        if successRate < 0.8 {
            log.Printf("WARNING: Low reCAPTCHA success rate: %.2f%%", successRate*100)
        }

        // Check average score
        avgScore := float64(metrics.AverageScore) / 100
        if avgScore < 0.5 {
            log.Printf("WARNING: Low average reCAPTCHA score: %.2f", avgScore)
        }

        // Check for suspicious patterns
        checkSuspiciousReCAPTCHAPatterns(metrics)
    }
}

// Check for suspicious patterns
func checkSuspiciousReCAPTCHAPatterns(metrics *reCAPTCHAMetrics) {
    // Check for too many perfect scores (potential bypass)
    perfectScores := metrics.ScoreDistribution["0.9-1.0"]
    if perfectScores > 1000 {
        log.Printf("ALERT: Suspicious number of perfect reCAPTCHA scores: %d", perfectScores)
    }

    // Check for score distribution anomalies
    lowScores := metrics.ScoreDistribution["0.0-0.3"]
    if lowScores > 500 {
        log.Printf("ALERT: High number of low reCAPTCHA scores: %d", lowScores)
    }
}
```

## Testing reCAPTCHA

### 1. Unit Tests

```go
func TestReCAPTCHAValidation(t *testing.T) {
    // Test valid token
    validToken := "valid-token"
    result := validateGoogleReCAPTCHAv2(validToken, "127.0.0.1")
    assert.True(t, result)

    // Test invalid token
    invalidToken := "invalid-token"
    result = validateGoogleReCAPTCHAv2(invalidToken, "127.0.0.1")
    assert.False(t, result)
}

func TestReCAPTCHAv3Scoring(t *testing.T) {
    // Test score threshold
    score, action, err := validateGoogleReCAPTCHAv3("valid-token", "127.0.0.1")
    assert.NoError(t, err)
    assert.Equal(t, "login", action)
    assert.Greater(t, score, 0.5)
}
```

### 2. Integration Tests

```go
func TestReCAPTCHAIntegration(t *testing.T) {
    // Setup test server
    r := gin.New()
    r.POST("/login", reCAPTCHAMiddleware(), loginHandler)

    // Test without reCAPTCHA token
    resp := performRequest(r, "POST", "/login", gin.H{
        "email": "test@example.com",
        "password": "password123",
    })
    assert.Equal(t, 400, resp.Code)

    // Test with valid reCAPTCHA token
    resp = performRequest(r, "POST", "/login", gin.H{
        "email": "test@example.com",
        "password": "password123",
        "recaptcha_token": "valid-token",
    })
    assert.Equal(t, 200, resp.Code)
}
```

## Best Practices

### 1. Configuration

- Use different site keys for different environments
- Set appropriate score thresholds for v3
- Monitor and adjust thresholds based on false positives/negatives

### 2. User Experience

- Use invisible reCAPTCHA when possible
- Provide clear error messages for failed validation
- Consider user trust scores for adaptive challenges

### 3. Security

- Always validate reCAPTCHA on the server side
- Use HTTPS for all reCAPTCHA communications
- Monitor for suspicious patterns and bypass attempts

### 4. Performance

- Load reCAPTCHA scripts asynchronously
- Cache validation results when appropriate
- Use CDN for reCAPTCHA resources

## Next Steps

- [Security Features](security.md) - Learn about other security measures
- [Rate Limiting](rate-limiting.md) - Combine with rate limiting
- [Configuration](../configuration/auth.md) - Configure reCAPTCHA settings
- [API Reference](../api/endpoints.md) - Explore reCAPTCHA endpoints
