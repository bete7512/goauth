# Notification Module Usage Guide

## Overview

The Notification Module provides a flexible way to send email and SMS notifications for authentication events. It includes:

- **Email Senders**: SendGrid, Resend, SMTP
- **SMS Senders**: Twilio
- **Custom Implementations**: Easily add your own senders
- **Event-Driven**: Automatically listens to auth events
- **Templates**: Pre-built templates for common notifications

## Quick Start

### 1. Using SendGrid for Email

```go
package main

import (
    "context"
    "github.com/bete7512/goauth/internal/modules/core"
    "github.com/bete7512/goauth/internal/modules/notification"
    "github.com/bete7512/goauth/internal/modules/notification/services"
    "github.com/bete7512/goauth/internal/modules/notification/services/senders"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
)

func main() {
    // Create storage
    store, _ := storage.NewStorage(config.StorageConfig{
        Driver:  "gorm",
        Dialect: "sqlite",
        DSN:     "./auth.db",
    })

    // Create SendGrid email sender
    emailSender := senders.NewSendGridEmailSender(&senders.SendGridConfig{
        APIKey:          "your-sendgrid-api-key",
        DefaultFrom:     "noreply@yourapp.com",
        DefaultFromName: "Your App",
    })

    // Create auth instance
    authInstance, _ := auth.New(&config.Config{
        Storage:   store,
        SecretKey: "your-secret-key",
    })

    // Register modules
    authInstance.Use(core.New(&core.Config{}))
    
    // Register notification module with SendGrid
    authInstance.Use(notification.New(&notification.Config{
        EmailSender: emailSender,
        ServiceConfig: &services.NotificationConfig{
            AppName:           "Your App",
            SupportEmail:      "support@yourapp.com",
            SupportLink:       "https://yourapp.com/support",
            EnableEmailAlerts: true,
        },
        EnableWelcomeEmail:        true,
        EnablePasswordResetEmail:  true,
        EnablePasswordChangeAlert: true,
    }))

    // Initialize
    authInstance.Initialize(context.Background())
}
```

### 2. Using Resend for Email

```go
// Create Resend email sender
emailSender := senders.NewResendEmailSender(&senders.ResendConfig{
    APIKey:          "your-resend-api-key",
    DefaultFrom:     "noreply@yourapp.com",
    DefaultFromName: "Your App",
})

authInstance.Use(notification.New(&notification.Config{
    EmailSender: emailSender,
    // ... rest of config
}))
```

### 3. Using SMTP for Email

```go
// Create SMTP email sender
emailSender := senders.NewSMTPEmailSender(&senders.SMTPConfig{
    Host:            "smtp.gmail.com",
    Port:            587,
    Username:        "your-email@gmail.com",
    Password:        "your-app-password",
    DefaultFrom:     "your-email@gmail.com",
    DefaultFromName: "Your App",
    UseTLS:          true,
})

authInstance.Use(notification.New(&notification.Config{
    EmailSender: emailSender,
    // ... rest of config
}))
```

### 4. Using Twilio for SMS

```go
// Create Twilio SMS sender
smsSender := senders.NewTwilioSMSSender(&senders.TwilioConfig{
    AccountSID: "your-twilio-account-sid",
    AuthToken:  "your-twilio-auth-token",
    FromNumber: "+1234567890", // Your Twilio phone number
})

authInstance.Use(notification.New(&notification.Config{
    SMSSender: smsSender,
    ServiceConfig: &services.NotificationConfig{
        EnableSMSAlerts: true,
    },
    EnablePasswordResetSMS: true,
    Enable2FANotifications: true,
}))
```

### 5. Using Both Email and SMS

```go
emailSender := senders.NewSendGridEmailSender(&senders.SendGridConfig{
    APIKey:          "your-sendgrid-api-key",
    DefaultFrom:     "noreply@yourapp.com",
    DefaultFromName: "Your App",
})

smsSender := senders.NewTwilioSMSSender(&senders.TwilioConfig{
    AccountSID: "your-twilio-account-sid",
    AuthToken:  "your-twilio-auth-token",
    FromNumber: "+1234567890",
})

authInstance.Use(notification.New(&notification.Config{
    EmailSender: emailSender,
    SMSSender:   smsSender,
    ServiceConfig: &services.NotificationConfig{
        AppName:           "Your App",
        EnableEmailAlerts: true,
        EnableSMSAlerts:   true,
    },
    EnableWelcomeEmail:        true,
    EnablePasswordResetEmail:  true,
    EnablePasswordResetSMS:    true,
    EnablePasswordChangeAlert: true,
    Enable2FANotifications:    true,
}))
```

## Custom Email Sender

Implement the `EmailSender` interface:

```go
package main

import (
    "context"
    "github.com/bete7512/goauth/internal/modules/notification/models"
)

type CustomEmailSender struct {
    // Your custom fields
}

func (c *CustomEmailSender) SendEmail(ctx context.Context, message *models.EmailMessage) error {
    // Your custom implementation
    // e.g., using AWS SES, Mailgun, Postmark, etc.
    return nil
}

func (c *CustomEmailSender) VerifyConnection(ctx context.Context) error {
    // Verify your service is reachable
    return nil
}

// Usage
customSender := &CustomEmailSender{}
authInstance.Use(notification.New(&notification.Config{
    EmailSender: customSender,
}))
```

## Custom SMS Sender

Implement the `SMSSender` interface:

```go
package main

import (
    "context"
    "github.com/bete7512/goauth/internal/modules/notification/models"
)

type CustomSMSSender struct {
    // Your custom fields
}

func (c *CustomSMSSender) SendSMS(ctx context.Context, message *models.SMSMessage) error {
    // Your custom implementation
    // e.g., using AWS SNS, Vonage, MessageBird, etc.
    return nil
}

func (c *CustomSMSSender) VerifyConnection(ctx context.Context) error {
    // Verify your service is reachable
    return nil
}

// Usage
customSender := &CustomSMSSender{}
authInstance.Use(notification.New(&notification.Config{
    SMSSender: customSender,
}))
```

## Custom Templates

Override default templates:

```go
customTemplates := map[string]models.NotificationTemplate{
    "welcome": {
        Name:      "welcome",
        Subject:   "Welcome to {{.AppName}}!",
        TextBody:  "Hi {{.UserName}}, thanks for joining!",
        HTMLBody:  "<h1>Hi {{.UserName}}!</h1><p>Thanks for joining {{.AppName}}!</p>",
        Enabled:   true,
        SendEmail: true,
        SendSMS:   false,
    },
    "password_reset": {
        Name:      "password_reset",
        Subject:   "Reset Your Password",
        TextBody:  "Reset link: {{.ResetLink}}",
        HTMLBody:  "<a href='{{.ResetLink}}'>Reset Password</a>",
        SMSBody:   "Your code: {{.Code}}",
        Enabled:   true,
        SendEmail: true,
        SendSMS:   true,
    },
}

authInstance.Use(notification.New(&notification.Config{
    EmailSender: emailSender,
    SMSSender:   smsSender,
    ServiceConfig: &services.NotificationConfig{
        AppName:   "Your App",
        Templates: customTemplates,
    },
}))
```

## Event Hooks

The notification module automatically listens to these events:

| Event | Description | Email | SMS |
|-------|-------------|-------|-----|
| `after:signup` | User signed up | Welcome email | - |
| `password:reset:request` | Password reset requested | Reset link | Reset code |
| `password:changed` | Password changed | Alert | - |
| `after:login` | User logged in | Login alert (optional) | - |
| `email:verification:sent` | Email verification | Verification link | - |
| `2fa:code:sent` | 2FA code sent | Code | Code |

### Triggering Events

Events are automatically triggered by the core module:

```go
// In your core module
deps.Events.Emit(ctx, "password:reset:request", map[string]interface{}{
    "email":        user.Email,
    "name":         user.Name,
    "reset_link":   resetLink,
    "code":         resetCode,
    "phone_number": user.PhoneNumber,
})

// Notification module will receive this and send email/SMS automatically
```

## Direct Service Access

Access the notification service directly:

```go
// Get the notification module
notifModule := notification.New(&notification.Config{
    EmailSender: emailSender,
})

authInstance.Use(notifModule)
authInstance.Initialize(context.Background())

// Direct access
service := notifModule.GetService()

// Send custom email
service.SendCustomEmail(ctx, &models.EmailMessage{
    To:       []string{"user@example.com"},
    Subject:  "Custom Notification",
    TextBody: "This is a custom message",
    HTMLBody: "<p>This is a <strong>custom</strong> message</p>",
})

// Send custom SMS
service.SendCustomSMS(ctx, &models.SMSMessage{
    To:   "+1234567890",
    Body: "Custom SMS notification",
})
```

## Configuration Options

### Module Config

```go
type Config struct {
    // Sender implementations
    EmailSender models.EmailSender
    SMSSender   models.SMSSender

    // Service configuration
    ServiceConfig *services.NotificationConfig

    // Enable/disable specific notifications
    EnableWelcomeEmail        bool // Default: true
    EnablePasswordResetEmail  bool // Default: true
    EnablePasswordResetSMS    bool // Default: false
    EnableLoginAlerts         bool // Default: false
    EnablePasswordChangeAlert bool // Default: true
    Enable2FANotifications    bool // Default: true
}
```

### Service Config

```go
type NotificationConfig struct {
    AppName           string
    SupportEmail      string
    SupportLink       string
    EnableEmailAlerts bool
    EnableSMSAlerts   bool
    Templates         map[string]models.NotificationTemplate
}
```

## Testing

### Mock Email Sender

```go
type MockEmailSender struct {
    SentEmails []*models.EmailMessage
}

func (m *MockEmailSender) SendEmail(ctx context.Context, message *models.EmailMessage) error {
    m.SentEmails = append(m.SentEmails, message)
    return nil
}

func (m *MockEmailSender) VerifyConnection(ctx context.Context) error {
    return nil
}

// Usage in tests
mockSender := &MockEmailSender{}
notifModule := notification.New(&notification.Config{
    EmailSender: mockSender,
})

// ... trigger events ...

// Verify
assert.Len(t, mockSender.SentEmails, 1)
assert.Equal(t, "Welcome!", mockSender.SentEmails[0].Subject)
```

## Environment Variables

```bash
# SendGrid
export SENDGRID_API_KEY="your-api-key"
export SENDGRID_FROM_EMAIL="noreply@yourapp.com"

# Resend
export RESEND_API_KEY="your-api-key"
export RESEND_FROM_EMAIL="noreply@yourapp.com"

# SMTP
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USERNAME="your-email@gmail.com"
export SMTP_PASSWORD="your-password"

# Twilio
export TWILIO_ACCOUNT_SID="your-account-sid"
export TWILIO_AUTH_TOKEN="your-auth-token"
export TWILIO_FROM_NUMBER="+1234567890"
```

## Production Best Practices

1. **Error Handling**: Notifications are non-blocking - errors are logged but don't stop the auth flow
2. **Rate Limiting**: Implement rate limiting on notification sending
3. **Queue System**: For high-volume apps, use a queue (Redis, RabbitMQ) for async processing
4. **Template Management**: Store templates in database for easy updates
5. **Analytics**: Track notification delivery rates and failures
6. **Retry Logic**: Implement retry logic for failed sends
7. **Cost Optimization**: Monitor and optimize email/SMS costs

## Examples

See `examples/notification_usage.go` for complete working examples.

## API Reference

### EmailSender Interface

```go
type EmailSender interface {
    SendEmail(ctx context.Context, message *EmailMessage) error
    VerifyConnection(ctx context.Context) error
}
```

### SMSSender Interface

```go
type SMSSender interface {
    SendSMS(ctx context.Context, message *SMSMessage) error
    VerifyConnection(ctx context.Context) error
}
```

### EmailMessage

```go
type EmailMessage struct {
    To          []string
    From        string
    FromName    string
    Subject     string
    TextBody    string
    HTMLBody    string
    CC          []string
    BCC         []string
    ReplyTo     string
    Attachments []Attachment
    Headers     map[string]string
}
```

### SMSMessage

```go
type SMSMessage struct {
    To      string   // E.164 format: +1234567890
    From    string
    Body    string
    MediaURL []string // For MMS
}
```


