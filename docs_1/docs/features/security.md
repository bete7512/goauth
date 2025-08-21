---
id: security
title: Security Features
sidebar_label: Security
sidebar_position: 5
---

# Security Features

GoAuth provides comprehensive security features to protect your authentication system from various threats and vulnerabilities.

## Overview

Security is a core principle of GoAuth. The library implements industry best practices and provides multiple layers of protection to ensure your authentication system remains secure.

## Core Security Features

### 1. Password Security

#### Password Hashing

GoAuth uses bcrypt for password hashing with configurable cost factors:

```go
// Password hashing configuration
cfg := &config.Config{
    Security: config.SecurityConfig{
        Password: config.PasswordConfig{
            MinLength:     8,
            RequireUppercase: true,
            RequireLowercase: true,
            RequireNumbers:   true,
            RequireSpecial:   true,
            BcryptCost:       12,
        },
    },
}

// Password validation
func validatePassword(password string) error {
    if len(password) < 8 {
        return errors.New("password must be at least 8 characters")
    }

    var (
        hasUpper   bool
        hasLower   bool
        hasNumber  bool
        hasSpecial bool
    )

    for _, char := range password {
        switch {
        case unicode.IsUpper(char):
            hasUpper = true
        case unicode.IsLower(char):
            hasLower = true
        case unicode.IsNumber(char):
            hasNumber = true
        case unicode.IsPunct(char) || unicode.IsSymbol(char):
            hasSpecial = true
        }
    }

    if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
        return errors.New("password must contain uppercase, lowercase, number, and special character")
    }

    return nil
}

// Password hashing
func hashPassword(password string) (string, error) {
    hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
    if err != nil {
        return "", err
    }
    return string(hashedBytes), nil
}

// Password verification
func verifyPassword(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}
```

#### Password History

Prevent password reuse:

```go
// Check password history
func checkPasswordHistory(userID string, newPassword string) error {
    // Get last 5 passwords
    recentPasswords, err := getRecentPasswords(userID, 5)
    if err != nil {
        return err
    }

    // Check if new password matches any recent password
    for _, oldHash := range recentPasswords {
        if verifyPassword(newPassword, oldHash) {
            return errors.New("password cannot be the same as recent passwords")
        }
    }

    return nil
}

// Update password with history
func updatePasswordWithHistory(userID string, newPassword string) error {
    // Check password history
    if err := checkPasswordHistory(userID, newPassword); err != nil {
        return err
    }

    // Hash new password
    hashedPassword, err := hashPassword(newPassword)
    if err != nil {
        return err
    }

    // Update password and add to history
    err = updatePassword(userID, hashedPassword)
    if err != nil {
        return err
    }

    return addPasswordToHistory(userID, hashedPassword)
}
```

### 2. CSRF Protection

#### CSRF Token Generation

```go
// CSRF token middleware
func CSRFMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        if c.Request.Method == "GET" {
            // Generate CSRF token for GET requests
            token := generateCSRFToken()
            c.Set("csrf_token", token)
            c.Header("X-CSRF-Token", token)
        } else {
            // Validate CSRF token for non-GET requests
            token := c.GetHeader("X-CSRF-Token")
            if !validateCSRFToken(token) {
                c.JSON(403, gin.H{"error": "Invalid CSRF token"})
                c.Abort()
                return
            }
        }
        c.Next()
    }
}

// Generate CSRF token
func generateCSRFToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}

// Validate CSRF token
func validateCSRFToken(token string) bool {
    // Implement token validation logic
    // This could involve checking against stored tokens or using cryptographic signatures
    return len(token) > 0
}
```

#### CSRF Token Validation

```go
// CSRF token validation in forms
func validateCSRFForm(c *gin.Context) {
    token := c.PostForm("csrf_token")
    if !validateCSRFToken(token) {
        c.JSON(403, gin.H{"error": "Invalid CSRF token"})
        c.Abort()
        return
    }
    c.Next()
}

// CSRF token validation in JSON requests
func validateCSRFJSON(c *gin.Context) {
    var req struct {
        CSRFToken string `json:"csrf_token" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "CSRF token required"})
        c.Abort()
        return
    }

    if !validateCSRFToken(req.CSRFToken) {
        c.JSON(403, gin.H{"error": "Invalid CSRF token"})
        c.Abort()
        return
    }

    c.Next()
}
```

### 3. Input Validation and Sanitization

#### Request Validation

```go
// Comprehensive request validation
type ValidationRules struct {
    Email     string `binding:"required,email"`
    Password  string `binding:"required,min=8,max=128"`
    Name      string `binding:"required,min=2,max=100"`
    Phone     string `binding:"omitempty,len=10"`
    Age       int    `binding:"omitempty,min=13,max=120"`
}

// Custom validation functions
func registerCustomValidations(v *validator.Validate) {
    v.RegisterValidation("phone", validatePhone)
    v.RegisterValidation("age", validateAge)
    v.RegisterValidation("password_strength", validatePasswordStrength)
}

// Phone number validation
func validatePhone(fl validator.FieldLevel) bool {
    phone := fl.Field().String()
    if phone == "" {
        return true // Allow empty phone numbers
    }

    // Basic phone number validation
    phoneRegex := regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
    return phoneRegex.MatchString(phone)
}

// Age validation
func validateAge(fl validator.FieldLevel) bool {
    age := fl.Field().Int()
    return age >= 13 && age <= 120
}

// Password strength validation
func validatePasswordStrength(fl validator.FieldLevel) bool {
    password := fl.Field().String()

    var (
        hasUpper   bool
        hasLower   bool
        hasNumber  bool
        hasSpecial bool
        length     = len(password)
    )

    if length < 8 || length > 128 {
        return false
    }

    for _, char := range password {
        switch {
        case unicode.IsUpper(char):
            hasUpper = true
        case unicode.IsLower(char):
            hasLower = true
        case unicode.IsNumber(char):
            hasNumber = true
        case unicode.IsPunct(char) || unicode.IsSymbol(char):
            hasSpecial = true
        }
    }

    return hasUpper && hasLower && hasNumber && hasSpecial
}
```

#### SQL Injection Prevention

```go
// Use parameterized queries
func getUserByEmail(db *sql.DB, email string) (*models.User, error) {
    query := `SELECT id, email, name FROM users WHERE email = $1`

    user := &models.User{}
    err := db.QueryRow(query, email).Scan(&user.ID, &user.Email, &user.Name)
    if err != nil {
        return nil, err
    }

    return user, nil
}

// Prevent SQL injection with proper escaping
func searchUsers(db *sql.DB, searchTerm string) ([]*models.User, error) {
    // Use LIKE with proper escaping
    query := `SELECT id, email, name FROM users WHERE name ILIKE $1 OR email ILIKE $1`

    rows, err := db.Query(query, "%"+searchTerm+"%")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var users []*models.User
    for rows.Next() {
        user := &models.User{}
        err := rows.Scan(&user.ID, &user.Email, &user.Name)
        if err != nil {
            return nil, err
        }
        users = append(users, user)
    }

    return users, nil
}
```

### 4. Session Security

#### Secure Session Management

```go
// Secure session configuration
cfg := &config.Config{
    Security: config.SecurityConfig{
        Session: config.SessionConfig{
            Secret:        "your-super-secret-session-key",
            Expiration:    24 * time.Hour,
            Secure:        true, // HTTPS only
            HttpOnly:      true, // Prevent XSS
            SameSite:      "strict",
            Domain:        ".yourdomain.com",
            Path:          "/",
            MaxAge:        86400, // 24 hours
        },
    },
}

// Session middleware with security headers
func SecureSessionMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Set security headers
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-XSS-Protection", "1; mode=block")
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
        c.Header("Content-Security-Policy", "default-src 'self'")

        c.Next()
    }
}
```

#### Session Hijacking Prevention

```go
// Session hijacking prevention
func preventSessionHijacking(c *gin.Context) {
    userID := c.GetString("user_id")
    if userID == "" {
        return
    }

    // Check if session fingerprint matches
    currentFingerprint := generateSessionFingerprint(c)
    storedFingerprint := getSessionFingerprint(userID)

    if storedFingerprint != "" && currentFingerprint != storedFingerprint {
        // Potential session hijacking
        log.Printf("Potential session hijacking detected for user: %s", userID)

        // Invalidate session
        invalidateSession(userID)

        c.JSON(401, gin.H{"error": "Session invalidated due to security concerns"})
        c.Abort()
        return
    }

    c.Next()
}

// Generate session fingerprint
func generateSessionFingerprint(c *gin.Context) string {
    userAgent := c.GetHeader("User-Agent")
    ip := c.ClientIP()

    // Create fingerprint from user agent and IP
    fingerprint := userAgent + "|" + ip
    hash := sha256.Sum256([]byte(fingerprint))

    return hex.EncodeToString(hash[:])
}
```

### 5. Brute Force Protection

#### Account Lockout

```go
// Account lockout after failed attempts
type LoginAttempt struct {
    UserID    string
    IP        string
    Timestamp time.Time
    Success   bool
}

// Check login attempts
func checkLoginAttempts(userID, ip string) error {
    attempts, err := getRecentLoginAttempts(userID, ip, 15*time.Minute)
    if err != nil {
        return err
    }

    failedAttempts := 0
    for _, attempt := range attempts {
        if !attempt.Success {
            failedAttempts++
        }
    }

    if failedAttempts >= 5 {
        return errors.New("account temporarily locked due to too many failed attempts")
    }

    return nil
}

// Record login attempt
func recordLoginAttempt(userID, ip string, success bool) error {
    attempt := &LoginAttempt{
        UserID:    userID,
        IP:        ip,
        Timestamp: time.Now(),
        Success:   success,
    }

    return storeLoginAttempt(attempt)
}

// Account lockout implementation
func implementAccountLockout(c *gin.Context) {
    userID := c.PostForm("email") // or from request body

    if err := checkLoginAttempts(userID, c.ClientIP()); err != nil {
        c.JSON(423, gin.H{"error": err.Error()})
        c.Abort()
        return
    }

    c.Next()
}
```

#### Progressive Delays

```go
// Progressive delay based on failed attempts
func getProgressiveDelay(userID string) time.Duration {
    failedAttempts := getFailedAttempts(userID, 1*time.Hour)

    switch {
    case failedAttempts <= 3:
        return 0
    case failedAttempts <= 5:
        return 1 * time.Minute
    case failedAttempts <= 10:
        return 5 * time.Minute
    case failedAttempts <= 15:
        return 15 * time.Minute
    default:
        return 1 * time.Hour
    }
}

// Apply progressive delay
func applyProgressiveDelay(c *gin.Context) {
    userID := c.PostForm("email")
    delay := getProgressiveDelay(userID)

    if delay > 0 {
        time.Sleep(delay)
    }

    c.Next()
}
```

## Advanced Security Features

### 1. Multi-Factor Authentication (MFA)

#### TOTP Implementation

```go
// TOTP-based MFA
func setupTOTP(userID string) (string, string, error) {
    // Generate secret
    secret := generateTOTPSecret()

    // Generate QR code
    qrCode := generateTOTPQRCode(userID, secret)

    // Store secret securely
    err := storeTOTPSecret(userID, secret)
    if err != nil {
        return "", "", err
    }

    return secret, qrCode, nil
}

// Verify TOTP code
func verifyTOTPCode(userID, code string) bool {
    secret, err := getTOTPSecret(userID)
    if err != nil {
        return false
    }

    return totp.Validate(code, secret)
}
```

#### SMS/Email Verification

```go
// SMS verification
func sendSMSVerification(phone string) (string, error) {
    code := generateVerificationCode()

    // Store code with expiration
    err := storeVerificationCode(phone, code, 5*time.Minute)
    if err != nil {
        return "", err
    }

    // Send SMS
    return code, sendSMS(phone, fmt.Sprintf("Your verification code is: %s", code))
}

// Email verification
func sendEmailVerification(email string) (string, error) {
    code := generateVerificationCode()

    // Store code with expiration
    err := storeVerificationCode(email, code, 10*time.Minute)
    if err != nil {
        return "", err
    }

    // Send email
    return code, sendVerificationEmail(email, code)
}
```

### 2. IP Whitelisting/Blacklisting

#### IP Filtering

```go
// IP whitelist middleware
func IPWhitelistMiddleware(allowedIPs []string) gin.HandlerFunc {
    return func(c *gin.Context) {
        clientIP := c.ClientIP()

        allowed := false
        for _, ip := range allowedIPs {
            if ip == clientIP || isIPInRange(clientIP, ip) {
                allowed = true
                break
            }
        }

        if !allowed {
            c.JSON(403, gin.H{"error": "Access denied from this IP address"})
            c.Abort()
            return
        }

        c.Next()
    }
}

// IP blacklist middleware
func IPBlacklistMiddleware(blockedIPs []string) gin.HandlerFunc {
    return func(c *gin.Context) {
        clientIP := c.ClientIP()

        for _, ip := range blockedIPs {
            if ip == clientIP || isIPInRange(clientIP, ip) {
                c.JSON(403, gin.H{"error": "Access denied from this IP address"})
                c.Abort()
                return
            }
        }

        c.Next()
    }
}

// Check if IP is in range (CIDR notation)
func isIPInRange(clientIP, cidr string) bool {
    _, network, err := net.ParseCIDR(cidr)
    if err != nil {
        return false
    }

    ip := net.ParseIP(clientIP)
    return network.Contains(ip)
}
```

### 3. Geographic Restrictions

#### Country-Based Access Control

```go
// Geographic access control
func GeographicAccessControl(allowedCountries []string) gin.HandlerFunc {
    return func(c *gin.Context) {
        clientIP := c.ClientIP()

        country, err := getCountryFromIP(clientIP)
        if err != nil {
            c.JSON(403, gin.H{"error": "Unable to determine location"})
            c.Abort()
            return
        }

        allowed := false
        for _, allowedCountry := range allowedCountries {
            if country == allowedCountry {
                allowed = true
                break
            }
        }

        if !allowed {
            c.JSON(403, gin.H{"error": "Access denied from this location"})
            c.Abort()
            return
        }

        c.Next()
    }
}

// Get country from IP (using external service)
func getCountryFromIP(ip string) (string, error) {
    // This would typically use a service like MaxMind GeoIP2
    // For demonstration, we'll use a simple approach

    resp, err := http.Get(fmt.Sprintf("http://ip-api.com/json/%s", ip))
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    var result struct {
        Country string `json:"country"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return "", err
    }

    return result.Country, nil
}
```

## Security Headers

### Comprehensive Security Headers

```go
// Security headers middleware
func SecurityHeadersMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Content Security Policy
        c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")

        // XSS Protection
        c.Header("X-XSS-Protection", "1; mode=block")

        // Content Type Options
        c.Header("X-Content-Type-Options", "nosniff")

        // Frame Options
        c.Header("X-Frame-Options", "DENY")

        // Referrer Policy
        c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

        // Strict Transport Security
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

        // Permissions Policy
        c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

        c.Next()
    }
}
```

### Dynamic Security Headers

```go
// Dynamic security headers based on request
func DynamicSecurityHeaders() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Set different CSP for different endpoints
        if strings.HasPrefix(c.Request.URL.Path, "/admin") {
            c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'")
        } else {
            c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
        }

        // Set different frame options for embedded content
        if strings.HasPrefix(c.Request.URL.Path, "/embed") {
            c.Header("X-Frame-Options", "SAMEORIGIN")
        } else {
            c.Header("X-Frame-Options", "DENY")
        }

        c.Next()
    }
}
```

## Security Monitoring and Logging

### Security Event Logging

```go
// Security event logging
type SecurityEvent struct {
    Timestamp   time.Time
    EventType   string
    UserID      string
    IP          string
    UserAgent   string
    Details     map[string]interface{}
    Severity    string
}

// Log security event
func logSecurityEvent(eventType, userID, ip, userAgent string, details map[string]interface{}, severity string) {
    event := &SecurityEvent{
        Timestamp: time.Now(),
        EventType: eventType,
        UserID:    userID,
        IP:        ip,
        UserAgent: userAgent,
        Details:   details,
        Severity:  severity,
    }

    // Store in database
    storeSecurityEvent(event)

    // Send to monitoring system if high severity
    if severity == "high" || severity == "critical" {
        sendSecurityAlert(event)
    }
}

// Security event types
const (
    EventLoginFailed     = "login_failed"
    EventAccountLocked   = "account_locked"
    EventPasswordChanged = "password_changed"
    Event2FAEnabled      = "2fa_enabled"
    Event2FADisabled     = "2fa_disabled"
    EventSuspiciousIP    = "suspicious_ip"
    EventBruteForce      = "brute_force_attempt"
)
```

### Real-time Security Monitoring

```go
// Real-time security monitoring
func monitorSecurityEvents() {
    ticker := time.NewTicker(1 * time.Minute)

    for range ticker.C {
        // Check for suspicious patterns
        checkSuspiciousPatterns()

        // Check for brute force attempts
        checkBruteForceAttempts()

        // Check for unusual login locations
        checkUnusualLocations()
    }
}

// Check for suspicious patterns
func checkSuspiciousPatterns() {
    // Implement pattern detection logic
    // This could involve machine learning or rule-based detection

    // Example: Multiple failed logins from different IPs
    failedLogins := getFailedLogins(5 * time.Minute)

    for userID, attempts := range failedLogins {
        if len(attempts) > 10 {
            logSecurityEvent(EventBruteForce, userID, "", "", map[string]interface{}{
                "attempts": len(attempts),
                "timeframe": "5 minutes",
            }, "high")
        }
    }
}
```

## Security Testing

### Security Test Suite

```go
func TestPasswordSecurity(t *testing.T) {
    // Test password strength validation
    weakPasswords := []string{"123", "password", "abc123", "qwerty"}
    for _, password := range weakPasswords {
        assert.Error(t, validatePassword(password))
    }

    strongPasswords := []string{"SecurePass123!", "MyP@ssw0rd", "Str0ng#Pass"}
    for _, password := range strongPasswords {
        assert.NoError(t, validatePassword(password))
    }
}

func TestCSRFProtection(t *testing.T) {
    // Test CSRF token validation
    validToken := generateCSRFToken()
    assert.True(t, validateCSRFToken(validToken))

    invalidToken := "invalid-token"
    assert.False(t, validateCSRFToken(invalidToken))
}

func TestBruteForceProtection(t *testing.T) {
    // Test brute force protection
    userID := "test-user"
    ip := "192.168.1.1"

    // Simulate failed attempts
    for i := 0; i < 5; i++ {
        recordLoginAttempt(userID, ip, false)
    }

    // Should be locked out
    err := checkLoginAttempts(userID, ip)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "account temporarily locked")
}
```

## Best Practices

### 1. Configuration Security

- Use strong, unique secrets for each environment
- Rotate secrets regularly
- Store secrets securely (environment variables, secret management systems)
- Use HTTPS in production

### 2. Code Security

- Validate and sanitize all inputs
- Use parameterized queries to prevent SQL injection
- Implement proper error handling without information leakage
- Keep dependencies updated

### 3. Infrastructure Security

- Use firewalls and network segmentation
- Implement proper access controls
- Monitor and log all security events
- Regular security audits and penetration testing

### 4. User Security

- Enforce strong password policies
- Implement account lockout mechanisms
- Provide security education to users
- Regular security awareness training

## Next Steps

- [Configuration](../configuration/auth.md) - Configure security settings
- [API Reference](../api/endpoints.md) - Explore security-related endpoints
- [Examples](../examples/basic-auth.md) - See security implementations
- [Testing](../tests/security.md) - Security testing guidelines
