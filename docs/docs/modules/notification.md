---
id: notification
title: Notification Module
sidebar_label: Notification Module
sidebar_position: 2
---

# Notification Module

The Notification Module handles email and SMS delivery for your auth system. It hooks into Core Module events to send verification emails, password reset links, welcome messages, and login alerts automatically. It does not expose any HTTP routes.

## Providers

- **Email**: SendGrid, SMTP, Resend
- **SMS**: Twilio

## Configuration

```go
import (
    "github.com/bete7512/goauth/internal/modules/notification"
    "github.com/bete7512/goauth/internal/modules/notification/services/senders"
)

a.Use(notification.New(&notification.Config{
    EmailSender: senders.NewSendGridEmailSender(&senders.SendGridConfig{
        APIKey:          "SG.xxxxx",
        DefaultFrom:     "noreply@yourapp.com",
        DefaultFromName: "Your App",
    }),

    SMSSender: senders.NewTwilioSMSSender(&senders.TwilioConfig{
        AccountSID: "ACxxxxx",
        AuthToken:  "your-auth-token",
        FromNumber: "+1234567890",
    }),

    EnableWelcomeEmail:        true,
    EnablePasswordResetEmail:  true,
    EnablePasswordResetSMS:    false,
    EnableLoginAlerts:         true,
    EnablePasswordChangeAlert: true,
    Enable2FANotifications:    false,
}))
```

## Email Providers

### SendGrid

```go
emailSender := senders.NewSendGridEmailSender(&senders.SendGridConfig{
    APIKey:          "SG.xxxxx",
    DefaultFrom:     "noreply@yourapp.com",
    DefaultFromName: "Your App",
})
```

### SMTP

```go
// Gmail
emailSender := senders.NewSMTPEmailSender(&senders.SMTPConfig{
    Host:     "smtp.gmail.com",
    Port:     587,
    Username: "your-email@gmail.com",
    Password: "your-16-char-app-password",
})

// Office 365
emailSender := senders.NewSMTPEmailSender(&senders.SMTPConfig{
    Host:     "smtp.office365.com",
    Port:     587,
    Username: "your-email@outlook.com",
    Password: "your-password",
})
```

### Resend

```go
emailSender := senders.NewResendEmailSender(&senders.ResendConfig{
    APIKey:          "re_xxxxx",
    DefaultFrom:     "noreply@yourapp.com",
    DefaultFromName: "Your App",
})
```

## SMS Provider

### Twilio

```go
smsSender := senders.NewTwilioSMSSender(&senders.TwilioConfig{
    AccountSID: "ACxxxxx",
    AuthToken:  "your-auth-token",
    FromNumber: "+1234567890",
})
```

## Event Hooks

The module hooks into Core events automatically:

| Event | Action | Config |
|-------|--------|--------|
| `EventAfterSignup` | Welcome or verification email | `EnableWelcomeEmail` |
| `EventBeforeForgotPassword` | Password reset email | `EnablePasswordResetEmail` |
| `EventAfterPasswordChange` | Password change alert | `EnablePasswordChangeAlert` |
| `EventAfterLogin` | Login alert | `EnableLoginAlerts` |
| Email verification requested | Verification email | Always enabled |
| Phone verification requested | SMS code | Requires SMS sender |

## Custom Templates

Override built-in templates:

```go
a.Use(notification.New(&notification.Config{
    EmailSender: emailSender,
    TemplateOverrides: map[string]string{
        "welcome":            "/path/to/welcome.html",
        "email_verification": "/path/to/verify.html",
        "password_reset":     "/path/to/reset.html",
    },
    // ... other config
}))
```

## Branding

Customize the look of built-in templates:

```go
a.Use(notification.New(&notification.Config{
    Branding: &templates.Branding{
        AppName:  "Your App",
        LogoURL:  "https://yourapp.com/logo.png",
        Color:    "#4F46E5",
    },
    // ... other config
}))
```

## Environment Variables

```bash
# SendGrid
SENDGRID_API_KEY=SG.xxxxx
EMAIL_FROM=noreply@yourapp.com

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

## Testing

Use [Mailtrap](https://mailtrap.io/) or [Ethereal](https://ethereal.email/) for dev:

```go
emailSender := senders.NewSMTPEmailSender(&senders.SMTPConfig{
    Host:     "smtp.ethereal.email",
    Port:     587,
    Username: "your-ethereal-username",
    Password: "your-ethereal-password",
})
```

## Next Steps

- [Core Module](core.md) — Core auth features
- [API Reference](/docs/api/endpoints) — All endpoints
