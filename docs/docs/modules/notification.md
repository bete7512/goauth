---
id: notification
title: Notification Module
sidebar_label: Notification Module
sidebar_position: 2
---

# Notification Module

The **Notification Module** provides email and SMS notifications for your authentication system. It's an optional module that integrates seamlessly with the Core Module to send verification emails, password reset emails, welcome emails, and more.

## Overview

The Notification Module handles all communication with your users through:
- **Email**: SendGrid, SMTP, Resend
- **SMS**: Twilio

It automatically hooks into Core Module events to send notifications at the right time.

## Features

### 📧 Email Notifications
- **Welcome Emails**: Send welcome emails after registration
- **Email Verification**: Send verification links to confirm email addresses
- **Password Reset**: Send secure password reset links
- **Password Change Alerts**: Notify users of password changes
- **Login Alerts**: Notify users of new logins (security feature)

### 📱 SMS Notifications
- **Phone Verification**: Send SMS codes for phone number verification
- **2FA Codes**: Send two-factor authentication codes (with Two-Factor module)
- **Password Reset via SMS**: Alternative password reset method

### 🎨 Template System
- Built-in HTML email templates
- Customizable templates
- Support for custom template providers

## Installation

The Notification Module is included with GoAuth. Just register it:

```go
import (
    "github.com/bete7512/goauth/internal/modules/notification"
    "github.com/bete7512/goauth/internal/modules/notification/services"
    "github.com/bete7512/goauth/internal/modules/notification/services/senders"
)
```

## Configuration

### Basic Configuration

```go
// After creating auth instance, before Initialize()
a.Use(notification.New(&notification.Config{
    // Email sender (choose one)
    EmailSender: senders.NewSendGridEmailSender(&senders.SendGridConfig{
        APIKey:          "your-sendgrid-api-key",
        DefaultFrom:     "noreply@yourapp.com",
        DefaultFromName: "Your App",
    }),
    
    // Or use SMTP
    // EmailSender: senders.NewSMTPEmailSender(&senders.SMTPConfig{...}),
    
    // SMS sender (optional)
    SMSSender: senders.NewTwilioSMSSender(&senders.TwilioConfig{
        AccountSID: "your-twilio-account-sid",
        AuthToken:  "your-twilio-auth-token",
        FromNumber: "+1234567890",
    }),
    
    // Service configuration
    ServiceConfig: &services.NotificationConfig{
        AppName:      "Your App Name",
        SupportEmail: "support@yourapp.com",
        SupportLink:  "https://yourapp.com/support",
    },
    
    // Enable specific notification types
    EnableWelcomeEmail:        true,
    EnablePasswordResetEmail:  true,
    EnablePasswordResetSMS:    false,
    EnableLoginAlerts:         true,
    EnablePasswordChangeAlert: true,
    Enable2FANotifications:    true,
}))
```

## Email Providers

### SendGrid

**Setup:**
1. Sign up at [SendGrid](https://sendgrid.com/)
2. Create an API key
3. Verify your sender email/domain

**Configuration:**
```go
emailSender := senders.NewSendGridEmailSender(&senders.SendGridConfig{
    APIKey:          "SG.xxxxx",
    DefaultFrom:     "noreply@yourapp.com",
    DefaultFromName: "Your App",
})
```

### SMTP (Gmail, Outlook, Custom)

**Gmail Setup:**
1. Enable 2FA on your Google account
2. Generate an [App Password](https://myaccount.google.com/apppasswords)
3. Use the app password (not your regular password)

**Configuration:**
```go
emailSender := senders.NewSMTPEmailSender(&senders.SMTPConfig{
    Host:     "smtp.gmail.com",
    Port:     587,
    Username: "your-email@gmail.com",
    Password: "your-16-char-app-password",
})
```

**Outlook/Office 365:**
```go
emailSender := senders.NewSMTPEmailSender(&senders.SMTPConfig{
    Host:     "smtp.office365.com",
    Port:     587,
    Username: "your-email@outlook.com",
    Password: "your-password",
})
```

**Custom SMTP Server:**
```go
emailSender := senders.NewSMTPEmailSender(&senders.SMTPConfig{
    Host:     "mail.yourserver.com",
    Port:     465,  // or 587
    Username: "smtp-user",
    Password: "smtp-password",
    UseTLS:   true,
})
```

### Resend

**Setup:**
1. Sign up at [Resend](https://resend.com/)
2. Create an API key
3. Verify your domain

**Configuration:**
```go
emailSender := senders.NewResendEmailSender(&senders.ResendConfig{
    APIKey:          "re_xxxxx",
    DefaultFrom:     "noreply@yourapp.com",
    DefaultFromName: "Your App",
})
```

## SMS Providers

### Twilio

**Setup:**
1. Sign up at [Twilio](https://www.twilio.com/)
2. Get your Account SID and Auth Token
3. Purchase a phone number

**Configuration:**
```go
smsSender := senders.NewTwilioSMSSender(&senders.TwilioConfig{
    AccountSID: "ACxxxxx",
    AuthToken:  "your-auth-token",
    FromNumber: "+1234567890",
})
```

## Notification Types

### Welcome Email

Sent after user registration (if `EnableWelcomeEmail: true` and email verification is not required).

**Automatic**: Sent via `EventAfterSignup` hook

**Template Variables:**
- `{{.UserName}}` - User's first name
- `{{.AppName}}` - Your app name
- `{{.LoginURL}}` - Link to login page

### Email Verification

Sent when user needs to verify their email address.

**Automatic**: Sent after signup if `RequireEmailVerification: true` in Core config

**Manual Trigger:**
```bash
POST /api/v1/send-verification-email
Authorization: Bearer <token>
```

**Template Variables:**
- `{{.VerificationURL}}` - Link to verify email
- `{{.AppName}}` - Your app name
- `{{.UserName}}` - User's name

### Password Reset Email

Sent when user requests a password reset.

**Automatic**: Sent via `POST /api/v1/forgot-password`

**Template Variables:**
- `{{.ResetURL}}` - Link to reset password
- `{{.AppName}}` - Your app name
- `{{.UserName}}` - User's name
- `{{.ExpiryTime}}` - Token expiry time

### Password Change Alert

Sent when user successfully changes their password.

**Automatic**: Sent via `EventAfterPasswordChange` hook

**Template Variables:**
- `{{.UserName}}` - User's name
- `{{.ChangeTime}}` - Time of password change
- `{{.IPAddress}}` - IP address of change
- `{{.SupportLink}}` - Link to support

### Login Alert

Sent when user logs in from a new device or location.

**Automatic**: Sent via `EventAfterLogin` hook (if `EnableLoginAlerts: true`)

**Template Variables:**
- `{{.UserName}}` - User's name
- `{{.LoginTime}}` - Time of login
- `{{.IPAddress}}` - IP address
- `{{.UserAgent}}` - Device/browser info
- `{{.Location}}` - Approximate location (if available)

### Phone Verification SMS

Sent when user needs to verify their phone number.

**Manual Trigger:**
```bash
POST /api/v1/send-verification-phone
Authorization: Bearer <token>
```

**SMS Content:**
```
Your verification code is: 123456
- Your App Name
```

## Custom Templates

### Using Custom Templates

```go
type CustomTemplateProvider struct {
    // Your template storage/logic
}

func (p *CustomTemplateProvider) GetTemplate(name string) (string, error) {
    // Return HTML template for the given name
    // Names: "welcome", "email_verification", "password_reset", etc.
}

// Use custom templates
a.Use(notification.New(&notification.Config{
    EmailSender: emailSender,
    TemplateProvider: &CustomTemplateProvider{},
    // ... other config
}))
```

### Template Names

Built-in templates:
- `welcome` - Welcome email
- `email_verification` - Email verification
- `password_reset` - Password reset
- `password_changed` - Password change alert
- `login_alert` - Login notification

## Events

The Notification Module hooks into Core Module events automatically:

| Core Event | Notification Action | Configurable |
|------------|-------------------|--------------|
| `EventAfterSignup` | Send welcome OR verification email | `EnableWelcomeEmail` |
| `EventBeforePasswordReset` | Send password reset email | `EnablePasswordResetEmail` |
| `EventAfterPasswordChange` | Send password change alert | `EnablePasswordChangeAlert` |
| `EventAfterLogin` | Send login alert | `EnableLoginAlerts` |
| Email verification requested | Send verification email | Always enabled |
| Phone verification requested | Send SMS code | Requires SMS sender |

## Complete Example

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/bete7512/goauth/internal/modules/notification"
    "github.com/bete7512/goauth/internal/modules/notification/services"
    "github.com/bete7512/goauth/internal/modules/notification/services/senders"
    "github.com/bete7512/goauth/internal/storage"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/types"
)

func main() {
    // Storage
    store, _ := storage.NewStorage(config.StorageConfig{
        Driver:  "gorm",
        Dialect: "postgres",
        DSN:     "host=localhost user=postgres password=secret dbname=authdb",
    })
    defer store.Close()

    // Auth
    a, _ := auth.New(&config.Config{
        Storage:     store,
        AutoMigrate: true,
        BasePath:    "/api/v1",
        Security: types.SecurityConfig{
            JwtSecretKey:  "your-secret-key-min-32-chars!!!!",
            EncryptionKey: "your-encryption-key-32-chars!",
            Session: types.SessionConfig{
                AccessTokenTTL:  15 * time.Minute,
                RefreshTokenTTL: 7 * 24 * time.Hour,
            },
        },
        Core: &config.CoreConfig{
            RequireEmailVerification: true,  // Will send verification emails
            RequirePhoneVerification: false,
        },
        FrontendConfig: &config.FrontendConfig{
            URL:                     "http://localhost:3000",
            VerifyEmailCallbackPath: "/verify-email",
            ResetPasswordPath:       "/reset-password",
        },
    })
    defer a.Close()

    // Register Notification Module
    a.Use(notification.New(&notification.Config{
        // Email via SendGrid
        EmailSender: senders.NewSendGridEmailSender(&senders.SendGridConfig{
            APIKey:          "SG.your-api-key",
            DefaultFrom:     "noreply@yourapp.com",
            DefaultFromName: "Your App",
        }),
        
        // SMS via Twilio (optional)
        SMSSender: senders.NewTwilioSMSSender(&senders.TwilioConfig{
            AccountSID: "ACxxxxx",
            AuthToken:  "your-auth-token",
            FromNumber: "+1234567890",
        }),
        
        // Service config
        ServiceConfig: &services.NotificationConfig{
            AppName:      "Your App",
            SupportEmail: "support@yourapp.com",
            SupportLink:  "https://yourapp.com/support",
        },
        
        // Enable notifications
        EnableWelcomeEmail:        false,  // Don't send if verification required
        EnablePasswordResetEmail:  true,
        EnablePasswordResetSMS:    false,
        EnableLoginAlerts:         true,
        EnablePasswordChangeAlert: true,
        Enable2FANotifications:    false,  // Enable with Two-Factor module
    }))

    // Initialize
    a.Initialize(context.Background())

    // Serve routes...
}
```

## Environment Variables

Store sensitive credentials in environment variables:

```env
# SendGrid
SENDGRID_API_KEY=SG.xxxxx
EMAIL_FROM=noreply@yourapp.com
EMAIL_FROM_NAME=Your App

# SMTP
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Twilio
TWILIO_ACCOUNT_SID=ACxxxxx
TWILIO_AUTH_TOKEN=xxxxx
TWILIO_FROM_NUMBER=+1234567890
```

**Load in code:**
```go
import "os"

emailSender := senders.NewSendGridEmailSender(&senders.SendGridConfig{
    APIKey:          os.Getenv("SENDGRID_API_KEY"),
    DefaultFrom:     os.Getenv("EMAIL_FROM"),
    DefaultFromName: os.Getenv("EMAIL_FROM_NAME"),
})
```

## Testing

### Test Email Sending

Use a test email service like [Mailtrap](https://mailtrap.io/) or [Ethereal](https://ethereal.email/) for development:

```go
// Ethereal SMTP (test emails)
emailSender := senders.NewSMTPEmailSender(&senders.SMTPConfig{
    Host:     "smtp.ethereal.email",
    Port:     587,
    Username: "your-ethereal-username",
    Password: "your-ethereal-password",
})
```

### Test SMS Sending

Twilio provides test credentials that don't send actual SMS messages.

## Troubleshooting

### Emails Not Sending

1. **Check API Keys**: Ensure your SendGrid/SMTP credentials are correct
2. **Check Sender Email**: Verify sender email with your provider
3. **Check Logs**: Look for error messages in your application logs
4. **Test Credentials**: Try sending a test email outside of GoAuth

### SMS Not Sending

1. **Check Twilio Balance**: Ensure your Twilio account has credits
2. **Check Phone Number**: Verify your Twilio phone number
3. **Check Number Format**: Use international format (+1234567890)

### Templates Not Working

1. **Check Template Names**: Ensure template names match built-in names
2. **Check Variables**: Verify all template variables are provided
3. **Test Templates**: Test templates independently

## Best Practices

1. **Use Environment Variables**: Never commit API keys to version control
2. **Verify Sender Email**: Always verify your sender email/domain
3. **Rate Limit Notifications**: Don't spam users with notifications
4. **Provide Unsubscribe**: Add unsubscribe options for marketing emails
5. **Test Thoroughly**: Test all notification types before production
6. **Monitor Deliverability**: Track email/SMS delivery rates
7. **Handle Failures Gracefully**: Don't block user actions if notifications fail

## Related Modules

- **[Core Module](core.md)** - Core authentication features
- **Two-Factor Module** - Requires Notification for SMS codes
- **Admin Module** - Can use notifications for user management

---

**The Notification Module brings your authentication system to life with timely, professional communications.**

