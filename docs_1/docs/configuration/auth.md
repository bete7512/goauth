---
id: auth
title: Authentication Configuration
sidebar_label: Authentication
sidebar_position: 1
---

# Authentication Configuration

GoAuth provides comprehensive configuration options to customize your authentication system according to your specific needs.

## Overview

The authentication configuration in GoAuth allows you to:

- Configure database connections
- Set security parameters
- Customize authentication flows
- Configure OAuth providers
- Set up notification systems
- Define storage backends

## Basic Configuration Structure

### Main Configuration

```go
package main

import (
    "time"
    "github.com/your-org/goauth/pkg/config"
)

func main() {
    cfg := &config.Config{
        Database:    config.DatabaseConfig{},
        Security:    config.SecurityConfig{},
        OAuth:       config.OAuthConfig{},
        Email:       config.EmailConfig{},
        SMS:         config.SMSConfig{},
        Storage:     config.StorageConfig{},
        Cache:       config.CacheConfig{},
        RateLimiting: config.RateLimitingConfig{},
        TwoFactor:   config.TwoFactorConfig{},
        reCAPTCHA:   config.reCAPTCHAConfig{},
    }

    // Initialize GoAuth with configuration
    auth, err := goauth.New(cfg)
    if err != nil {
        log.Fatal("Failed to initialize GoAuth:", err)
    }
}
```

## Database Configuration

### PostgreSQL Configuration

```go
cfg := &config.Config{
    Database: config.DatabaseConfig{
        Driver: "postgres",
        DSN:    "postgres://username:password@localhost/goauth?sslmode=disable",
        Options: config.DatabaseOptions{
            MaxOpenConns:    25,
            MaxIdleConns:    25,
            ConnMaxLifetime: 5 * time.Minute,
            ConnMaxIdleTime: 1 * time.Minute,
        },
    },
}
```

### MySQL Configuration

```go
cfg := &config.Config{
    Database: config.DatabaseConfig{
        Driver: "mysql",
        DSN:    "username:password@tcp(localhost:3306)/goauth?parseTime=true",
        Options: config.DatabaseOptions{
            MaxOpenConns:    25,
            MaxIdleConns:    25,
            ConnMaxLifetime: 5 * time.Minute,
            ConnMaxIdleTime: 1 * time.Minute,
        },
    },
}
```

### SQLite Configuration

```go
cfg := &config.Config{
    Database: config.DatabaseConfig{
        Driver: "sqlite3",
        DSN:    "./goauth.db",
        Options: config.DatabaseOptions{
            MaxOpenConns:    1,
            MaxIdleConns:    1,
            ConnMaxLifetime: 0,
            ConnMaxIdleTime: 0,
        },
    },
}
```

### Environment Variables for Database

```bash
# Database configuration
DB_DRIVER=postgres
DB_HOST=localhost
DB_PORT=5432
DB_NAME=goauth
DB_USER=goauth_user
DB_PASSWORD=secure_password
DB_SSL_MODE=disable

# Connection pool settings
DB_MAX_OPEN_CONNS=25
DB_MAX_IDLE_CONNS=25
DB_CONN_MAX_LIFETIME=5m
DB_CONN_MAX_IDLE_TIME=1m
```

## Security Configuration

### JWT Configuration

```go
cfg := &config.Config{
    Security: config.SecurityConfig{
        JWTSecret:        "your-super-secret-jwt-key-here",
        JWTExpiration:    24 * time.Hour,
        RefreshExpiration: 7 * 24 * time.Hour,
        JWTIssuer:        "goauth",
        JWTAudience:      "your-app",
        JWTAlgorithm:     "HS256",
        JWTKeyID:         "key-1",
        JWTClaims: map[string]interface{}{
            "version": "1.0",
            "app":     "myapp",
        },
    },
}
```

### Password Security

```go
cfg := &config.Config{
    Security: config.SecurityConfig{
        Password: config.PasswordConfig{
            MinLength:        8,
            MaxLength:        128,
            RequireUppercase: true,
            RequireLowercase: true,
            RequireNumbers:   true,
            RequireSpecial:   true,
            BcryptCost:       12,
            HistorySize:      5,
            ExpirationDays:   90,
        },
    },
}
```

### Session Security

```go
cfg := &config.Config{
    Security: config.SecurityConfig{
        Session: config.SessionConfig{
            Secret:        "your-super-secret-session-key",
            Expiration:    24 * time.Hour,
            Secure:        true,
            HttpOnly:      true,
            SameSite:      "strict",
            Domain:        ".yourdomain.com",
            Path:          "/",
            MaxAge:        86400,
        },
    },
}
```

### CSRF Protection

```go
cfg := &config.Config{
    Security: config.SecurityConfig{
        CSRF: config.CSRFConfig{
            Enabled:     true,
            Secret:      "your-csrf-secret",
            Expiration:  1 * time.Hour,
            HeaderName:  "X-CSRF-Token",
            FormField:   "csrf_token",
            CookieName:  "csrf_token",
        },
    },
}
```

## OAuth Configuration

### Google OAuth

```go
cfg := &config.Config{
    OAuth: config.OAuthConfig{
        Providers: map[string]config.OAuthProvider{
            "google": {
                ClientID:     "your-google-client-id",
                ClientSecret: "your-google-client-secret",
                RedirectURL:  "https://yourdomain.com/auth/oauth/google/callback",
                Scopes: []string{
                    "openid",
                    "email",
                    "profile",
                    "https://www.googleapis.com/auth/calendar.readonly",
                },
                AdditionalParams: map[string]string{
                    "access_type": "offline",
                    "prompt":      "consent",
                },
            },
        },
    },
}
```

### GitHub OAuth

```go
cfg := &config.Config{
    OAuth: config.OAuthConfig{
        Providers: map[string]config.OAuthProvider{
            "github": {
                ClientID:     "your-github-client-id",
                ClientSecret: "your-github-client-secret",
                RedirectURL:  "https://yourdomain.com/auth/oauth/github/callback",
                Scopes: []string{
                    "user:email",
                    "read:user",
                    "repo",
                    "gist",
                },
            },
        },
    },
}
```

### Facebook OAuth

```go
cfg := &config.Config{
    OAuth: config.OAuthConfig{
        Providers: map[string]config.OAuthProvider{
            "facebook": {
                ClientID:     "your-facebook-client-id",
                ClientSecret: "your-facebook-client-secret",
                RedirectURL:  "https://yourdomain.com/auth/oauth/facebook/callback",
                Scopes: []string{
                    "email",
                    "public_profile",
                    "user_posts",
                    "user_photos",
                },
            },
        },
    },
}
```

### Environment Variables for OAuth

```bash
# Google OAuth
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URL=https://yourdomain.com/auth/oauth/google/callback

# GitHub OAuth
GITHUB_CLIENT_ID=your-client-id
GITHUB_CLIENT_SECRET=your-client-secret
GITHUB_REDIRECT_URL=https://yourdomain.com/auth/oauth/github/callback

# Facebook OAuth
FACEBOOK_CLIENT_ID=your-client-id
FACEBOOK_CLIENT_SECRET=your-client-secret
FACEBOOK_REDIRECT_URL=https://yourdomain.com/auth/oauth/facebook/callback
```

## Email Configuration

### SMTP Configuration

```go
cfg := &config.Config{
    Email: config.EmailConfig{
        Provider: "smtp",
        SMTP: config.SMTPConfig{
            Host:         "smtp.gmail.com",
            Port:         587,
            Username:     "your-email@gmail.com",
            Password:     "your-app-password",
            FromEmail:    "noreply@yourdomain.com",
            FromName:     "Your App",
            Encryption:   "tls",
            AuthType:     "plain",
            Timeout:      10 * time.Second,
        },
    },
}
```

### SendGrid Configuration

```go
cfg := &config.Config{
    Email: config.EmailConfig{
        Provider: "sendgrid",
        SendGrid: config.SendGridConfig{
            APIKey:     "your-sendgrid-api-key",
            FromEmail:  "noreply@yourdomain.com",
            FromName:   "Your App",
            Timeout:    10 * time.Second,
        },
    },
}
```

### AWS SES Configuration

```go
cfg := &config.Config{
    Email: config.EmailConfig{
        Provider: "ses",
        SES: config.SESConfig{
            Region:     "us-east-1",
            AccessKey:  "your-access-key",
            SecretKey:  "your-secret-key",
            FromEmail:  "noreply@yourdomain.com",
            FromName:   "Your App",
            Timeout:    10 * time.Second,
        },
    },
}
```

### Email Templates

```go
cfg := &config.Config{
    Email: config.EmailConfig{
        Templates: config.EmailTemplates{
            Welcome: config.EmailTemplate{
                Subject: "Welcome to {{.AppName}}",
                HTML:    "./templates/welcome.html",
                Text:    "./templates/welcome.txt",
            },
            PasswordReset: config.EmailTemplate{
                Subject: "Reset Your Password",
                HTML:    "./templates/password_reset.html",
                Text:    "./templates/password_reset.txt",
            },
            EmailVerification: config.EmailTemplate{
                Subject: "Verify Your Email",
                HTML:    "./templates/email_verification.html",
                Text:    "./templates/email_verification.txt",
            },
        },
    },
}
```

## SMS Configuration

### Twilio Configuration

```go
cfg := &config.Config{
    SMS: config.SMSConfig{
        Provider: "twilio",
        Twilio: config.TwilioConfig{
            AccountSID: "your-account-sid",
            AuthToken:  "your-auth-token",
            FromNumber: "+1234567890",
            Timeout:    10 * time.Second,
        },
    },
}
```

### AWS SNS Configuration

```go
cfg := &config.Config{
    SMS: config.SMSConfig{
        Provider: "sns",
        SNS: config.SNSConfig{
            Region:     "us-east-1",
            AccessKey:  "your-access-key",
            SecretKey:  "your-secret-key",
            FromNumber: "+1234567890",
            Timeout:    10 * time.Second,
        },
    },
}
```

### Custom SMS Provider

```go
cfg := &config.Config{
    SMS: config.SMSConfig{
        Provider: "custom",
        Custom: config.CustomSMSConfig{
            Endpoint:   "https://your-sms-provider.com/api/send",
            APIKey:     "your-api-key",
            Timeout:    10 * time.Second,
            Headers: map[string]string{
                "Authorization": "Bearer {{.APIKey}}",
                "Content-Type":  "application/json",
            },
        },
    },
}
```

## Storage Configuration

### Redis Configuration

```go
cfg := &config.Config{
    Storage: config.StorageConfig{
        Cache: config.CacheConfig{
            Provider: "redis",
            Redis: config.RedisConfig{
                Addr:     "localhost:6379",
                Password: "",
                DB:       0,
                PoolSize: 10,
                MinIdleConns: 5,
                MaxRetries:   3,
                Timeout:      5 * time.Second,
            },
        },
        Session: config.SessionConfig{
            Provider: "redis",
            Redis: config.RedisConfig{
                Addr:     "localhost:6379",
                Password: "",
                DB:       1,
                PoolSize: 10,
                MinIdleConns: 5,
                MaxRetries:   3,
                Timeout:      5 * time.Second,
            },
        },
    },
}
```

### In-Memory Configuration

```go
cfg := &config.Config{
    Storage: config.StorageConfig{
        Cache: config.CacheConfig{
            Provider: "memory",
            Memory: config.MemoryConfig{
                DefaultExpiration: 5 * time.Minute,
                CleanupInterval:   10 * time.Minute,
            },
        },
        Session: config.SessionConfig{
            Provider: "memory",
            Memory: config.MemoryConfig{
                DefaultExpiration: 24 * time.Hour,
                CleanupInterval:   1 * time.Hour,
            },
        },
    },
}
```

## Rate Limiting Configuration

### Basic Rate Limiting

```go
cfg := &config.Config{
    RateLimiting: config.RateLimitingConfig{
        Enabled: true,
        Strategy: "sliding_window",
        Default: config.RateLimit{
            Window:  1 * time.Minute,
            Limit:   100,
            Burst:   10,
        },
        Endpoints: map[string]config.RateLimit{
            "/api/auth/login": {
                Window:  1 * time.Minute,
                Limit:   5,
                Burst:   1,
            },
            "/api/auth/register": {
                Window:  1 * time.Hour,
                Limit:   3,
                Burst:   1,
            },
            "/api/auth/forgot-password": {
                Window:  1 * time.Hour,
                Limit:   3,
                Burst:   1,
            },
        },
    },
}
```

### Advanced Rate Limiting

```go
cfg := &config.Config{
    RateLimiting: config.RateLimitingConfig{
        Enabled: true,
        Strategy: "token_bucket",
        Default: config.RateLimit{
            Window:  1 * time.Minute,
            Limit:   100,
            Burst:   20,
        },
        IPBased: config.IPRateLimit{
            Enabled: true,
            Window:  1 * time.Minute,
            Limit:   50,
            Burst:   5,
        },
        UserBased: config.UserRateLimit{
            Enabled: true,
            Window:  1 * time.Minute,
            Limit:   200,
            Burst:   25,
        },
        Endpoints: map[string]config.RateLimit{
            "/api/auth/login": {
                Window:  1 * time.Minute,
                Limit:   5,
                Burst:   1,
            },
        },
    },
}
```

## Two-Factor Authentication Configuration

### TOTP Configuration

```go
cfg := &config.Config{
    TwoFactor: config.TwoFactorConfig{
        Enabled: true,
        Methods: []string{"totp", "sms", "email"},
        TOTP: config.TOTPConfig{
            Algorithm: "SHA1",
            Digits:    6,
            Period:    30,
            Window:    1,
            Issuer:    "Your App",
        },
        SMS: config.SMS2FAConfig{
            CodeLength: 6,
            Expiration: 5 * time.Minute,
            MaxAttempts: 3,
        },
        Email: config.Email2FAConfig{
            CodeLength: 6,
            Expiration: 10 * time.Minute,
            MaxAttempts: 3,
        },
        BackupCodes: config.BackupCodesConfig{
            Enabled: true,
            Count:    10,
            Length:   8,
        },
    },
}
```

## reCAPTCHA Configuration

### Google reCAPTCHA

```go
cfg := &config.Config{
    reCAPTCHA: config.reCAPTCHAConfig{
        Enabled: true,
        Provider: "google",
        Google: config.GooglereCAPTCHAConfig{
            SiteKey:     "your-site-key",
            SecretKey:   "your-secret-key",
            Version:     "v3",
            Threshold:   0.5,
            Action:      "login",
        },
    },
}
```

### Cloudflare Turnstile

```go
cfg := &config.Config{
    reCAPTCHA: config.reCAPTCHAConfig{
        Enabled: true,
        Provider: "cloudflare",
        Cloudflare: config.CloudflareConfig{
            SiteKey:   "your-turnstile-site-key",
            SecretKey: "your-turnstile-secret-key",
        },
    },
}
```

## Environment-Based Configuration

### Configuration Loading

```go
package main

import (
    "os"
    "strconv"
    "time"
    "github.com/joho/godotenv"
    "github.com/your-org/goauth/pkg/config"
)

func main() {
    // Load environment variables
    if err := godotenv.Load(); err != nil {
        log.Printf("Warning: .env file not found")
    }

    cfg := loadConfigFromEnv()

    // Initialize GoAuth
    auth, err := goauth.New(cfg)
    if err != nil {
        log.Fatal("Failed to initialize GoAuth:", err)
    }
}

func loadConfigFromEnv() *config.Config {
    return &config.Config{
        Database: config.DatabaseConfig{
            Driver: getEnv("DB_DRIVER", "postgres"),
            DSN:    getDatabaseDSN(),
            Options: config.DatabaseOptions{
                MaxOpenConns:    getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
                MaxIdleConns:    getEnvAsInt("DB_MAX_IDLE_CONNS", 25),
                ConnMaxLifetime: getEnvAsDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
                ConnMaxIdleTime: getEnvAsDuration("DB_CONN_MAX_IDLE_TIME", 1*time.Minute),
            },
        },
        Security: config.SecurityConfig{
            JWTSecret:        getEnv("JWT_SECRET", "default-secret"),
            JWTExpiration:    getEnvAsDuration("JWT_EXPIRATION", 24*time.Hour),
            RefreshExpiration: getEnvAsDuration("REFRESH_EXPIRATION", 7*24*time.Hour),
        },
        // ... other configurations
    }
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
    if value := os.Getenv(key); value != "" {
        if intValue, err := strconv.Atoi(value); err == nil {
            return intValue
        }
    }
    return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
    if value := os.Getenv(key); value != "" {
        if duration, err := time.ParseDuration(value); err == nil {
            return duration
        }
    }
    return defaultValue
}

func getDatabaseDSN() string {
    driver := getEnv("DB_DRIVER", "postgres")

    switch driver {
    case "postgres":
        return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
            getEnv("DB_USER", "postgres"),
            getEnv("DB_PASSWORD", ""),
            getEnv("DB_HOST", "localhost"),
            getEnv("DB_PORT", "5432"),
            getEnv("DB_NAME", "goauth"),
            getEnv("DB_SSL_MODE", "disable"),
        )
    case "mysql":
        return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
            getEnv("DB_USER", "root"),
            getEnv("DB_PASSWORD", ""),
            getEnv("DB_HOST", "localhost"),
            getEnv("DB_PORT", "3306"),
            getEnv("DB_NAME", "goauth"),
        )
    case "sqlite3":
        return getEnv("DB_PATH", "./goauth.db")
    default:
        return ""
    }
}
```

## Configuration Validation

### Validate Configuration

```go
func validateConfig(cfg *config.Config) error {
    var errors []string

    // Validate database configuration
    if cfg.Database.DSN == "" {
        errors = append(errors, "database DSN is required")
    }

    // Validate security configuration
    if cfg.Security.JWTSecret == "" {
        errors = append(errors, "JWT secret is required")
    }

    if len(cfg.Security.JWTSecret) < 32 {
        errors = append(errors, "JWT secret must be at least 32 characters")
    }

    // Validate OAuth configuration
    for provider, config := range cfg.OAuth.Providers {
        if config.ClientID == "" {
            errors = append(errors, fmt.Sprintf("OAuth client ID is required for %s", provider))
        }
        if config.ClientSecret == "" {
            errors = append(errors, fmt.Sprintf("OAuth client secret is required for %s", provider))
        }
    }

    // Validate email configuration
    if cfg.Email.Provider == "smtp" {
        if cfg.Email.SMTP.Host == "" {
            errors = append(errors, "SMTP host is required")
        }
        if cfg.Email.SMTP.Username == "" {
            errors = append(errors, "SMTP username is required")
        }
        if cfg.Email.SMTP.Password == "" {
            errors = append(errors, "SMTP password is required")
        }
    }

    if len(errors) > 0 {
        return fmt.Errorf("configuration validation failed: %s", strings.Join(errors, "; "))
    }

    return nil
}
```

## Configuration Hot Reloading

### Watch Configuration Changes

```go
func watchConfigChanges(configPath string, reloadChan chan<- *config.Config) {
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        log.Printf("Failed to create config watcher: %v", err)
        return
    }
    defer watcher.Close()

    // Watch config file
    if err := watcher.Add(configPath); err != nil {
        log.Printf("Failed to watch config file: %v", err)
        return
    }

    for {
        select {
        case event := <-watcher.Events:
            if event.Op&fsnotify.Write == fsnotify.Write {
                log.Println("Config file changed, reloading...")

                // Reload configuration
                if newCfg, err := loadConfig(configPath); err == nil {
                    reloadChan <- newCfg
                } else {
                    log.Printf("Failed to reload config: %v", err)
                }
            }
        case err := <-watcher.Errors:
            log.Printf("Config watcher error: %v", err)
        }
    }
}

func loadConfig(configPath string) (*config.Config, error) {
    // Implementation depends on your config format (JSON, YAML, etc.)
    data, err := os.ReadFile(configPath)
    if err != nil {
        return nil, err
    }

    var cfg config.Config
    if err := json.Unmarshal(data, &cfg); err != nil {
        return nil, err
    }

    return &cfg, nil
}
```

## Best Practices

### 1. Security

- Use strong, unique secrets for each environment
- Store sensitive configuration in environment variables
- Use HTTPS in production
- Regularly rotate secrets

### 2. Environment Management

- Use different configurations for different environments
- Validate configuration on startup
- Provide sensible defaults
- Use configuration management tools

### 3. Performance

- Use connection pooling for databases
- Configure appropriate timeouts
- Monitor configuration impact on performance
- Use caching where appropriate

### 4. Monitoring

- Log configuration changes
- Monitor configuration validation errors
- Track configuration-related issues
- Use configuration health checks

## Next Steps

- [Security Configuration](security.md) - Configure security settings
- [Storage Configuration](storage.md) - Configure storage backends
- [Notification Configuration](notification.md) - Configure email and SMS
- [API Reference](../api/endpoints.md) - Explore configuration endpoints
