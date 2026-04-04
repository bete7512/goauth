---
id: notification
title: Notification Module
sidebar_label: Notification
sidebar_position: 2
---

# Notification Module

The Notification Module is GoAuth's delivery layer for all transactional email and SMS communication. It subscribes to events emitted by other modules (Core, Two-Factor, Magic Link) and automatically delivers the appropriate message — verification emails, password reset links, welcome messages, login alerts, 2FA codes, and magic links. It does not expose any HTTP routes and does not own any business logic; it is a pure, event-driven delivery layer.

The module is designed to be fully pluggable. You can use the built-in senders for common providers, or implement the `EmailSender` / `SMSSender` interfaces to integrate any email or SMS service. Templates are customizable per message type with branding injection.

## Capabilities

- **Automatic Event-Driven Delivery** — Subscribes to lifecycle events and sends the right message automatically. No manual "send email" calls needed in your application code.
- **Multiple Email Providers** — Built-in support for SendGrid, SMTP, and Resend. Switch providers by changing one line of configuration.
- **SMS Delivery** — Built-in Twilio integration for phone verification OTPs, password reset codes, login alerts, and 2FA codes.
- **Pluggable Senders** — Implement `EmailSender` or `SMSSender` to integrate any provider (Amazon SES, Mailgun, Postmark, MessageBird, Vonage, etc.).
- **Custom Templates** — Override any built-in email or SMS template with your own. Templates support Go template syntax with automatic branding variable injection.
- **Branding** — Configure app name, logo, colors, footer text, and contact email once. Every template receives these values automatically.
- **Per-Feature Toggle** — Enable or disable each notification type independently (welcome email, login alerts, password change alerts, 2FA notifications, magic link emails).
- **Template Defaults** — Call `DefaultEmailTemplates()` or `DefaultSMSTemplates()` to get the full default template map as a starting point for customization.

## Pluggable Infrastructure

The Notification module accepts any implementation of these interfaces. This is the primary extensibility point — implement one or both to use your preferred email/SMS provider:

```go
type EmailSender interface {
    // SendEmail delivers an email message. Return an error to indicate delivery failure.
    SendEmail(ctx context.Context, message *EmailMessage) error

    // VerifyConfig validates the sender configuration at module init time.
    VerifyConfig(ctx context.Context) error
}

type SMSSender interface {
    // SendSMS delivers an SMS message. Return an error to indicate delivery failure.
    SendSMS(ctx context.Context, message *SMSMessage) error

    // VerifyConfig validates the sender configuration at module init time.
    VerifyConfig(ctx context.Context) error
}
```

Pass your custom sender in the module config:

```go
a.Use(notification.New(&notification.Config{
    EmailSender: myCustomEmailSender, // implements notification.EmailSender
    SMSSender:   myCustomSMSSender,   // implements notification.SMSSender
}))
```

### Built-in Senders

| Provider | Type | Constructor |
|----------|------|-------------|
| **SendGrid** | Email | `senders.NewSendGridEmailSender(&senders.SendGridConfig{...})` |
| **SMTP** | Email | `senders.NewSMTPEmailSender(&senders.SMTPConfig{...})` |
| **Resend** | Email | `senders.NewResendEmailSender(&senders.ResendConfig{...})` |
| **Twilio** | SMS | `senders.NewTwilioSMSSender(&senders.TwilioConfig{...})` |

## Providers

- **Email**: SendGrid, SMTP, Resend (or any custom `EmailSender` implementation)
- **SMS**: Twilio (or any custom `SMSSender` implementation)

## Registration

```go
import (
    "github.com/bete7512/goauth/pkg/modules/notification"
    "github.com/bete7512/goauth/pkg/modules/notification/senders"
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

    Branding: &notification.Branding{
        AppName:      "Your App",
        LogoURL:      "https://yourapp.com/logo.png",
        PrimaryColor: "#4F46E5",
        TextColor:    "#333333",
        ContactEmail: "support@yourapp.com",
        DomainName:   "yourapp.com",
        FooterText:   "(c) 2026 Your App. All rights reserved.",
    },

    EnableWelcomeEmail:        true,
    EnablePasswordResetEmail:  true,
    EnablePasswordResetSMS:    false,
    EnableLoginAlerts:         true,
    EnablePasswordChangeAlert: true,
    Enable2FANotifications:    true,
    EnableMagicLinkEmail:      false,
}))
```

Pass `nil` for default config (welcome email + password reset email enabled, other flags off).

## Configuration

```go
type Config struct {
    EmailSender             notification.EmailSender            // Email provider (optional)
    SMSSender               notification.SMSSender              // SMS provider (optional)
    Branding                *notification.Branding              // Template branding (optional)
    EmailTemplates          map[string]notification.EmailTemplate // Override email templates by name
    SMSTemplates            map[string]notification.SMSTemplate   // Override SMS templates by name
    EnableWelcomeEmail      bool
    EnablePasswordResetEmail  bool
    EnablePasswordResetSMS    bool
    EnableLoginAlerts         bool
    EnablePasswordChangeAlert bool
    Enable2FANotifications    bool
    EnableMagicLinkEmail      bool
}
```

## Branding

The `Branding` struct is injected into every email template automatically:

```go
type Branding struct {
    AppName      string // e.g. "Acme Corp" -- used in subject lines and headings
    LogoURL      string // Absolute URL to product logo (displayed in email header)
    PrimaryColor string // Hex color for buttons and header background, e.g. "#007bff"
    TextColor    string // Hex color for body text, defaults to "#333333"
    ContactEmail string // Support email shown in footer
    DomainName   string // Product domain shown in footer
    FooterText   string // Custom footer line
}
```

If nil, defaults to `AppName: "GoAuth"`, `PrimaryColor: "#007bff"`, `TextColor: "#333333"`.

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
emailSender := senders.NewSMTPEmailSender(&senders.SMTPConfig{
    Host:            "smtp.gmail.com",
    Port:            587,
    Username:        "your-email@gmail.com",
    Password:        "your-16-char-app-password",
    DefaultFrom:     "noreply@yourapp.com",
    DefaultFromName: "Your App",
    UseTLS:          true,
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

## Custom Templates

Override built-in templates by providing `EmailTemplates` or `SMSTemplates` maps:

```go
a.Use(notification.New(&notification.Config{
    EmailSender: emailSender,
    EmailTemplates: map[string]notification.EmailTemplate{
        "welcome": {
            Name:     "welcome",
            Subject:  "Welcome to {{.Brand.AppName}}!",
            TextBody: "Hi {{.UserName}}, welcome!",
            HTMLBody: "<h1>Welcome {{.UserName}}</h1>",
        },
    },
    SMSTemplates: map[string]notification.SMSTemplate{
        "password_reset": {
            Name: "password_reset",
            Body: "{{.Brand.AppName}}: Reset code {{.Code}}, valid {{.ExpiryTime}}.",
        },
    },
}))
```

### Built-in email template names

`welcome`, `email_verification`, `password_reset`, `password_changed`, `two_factor_code`, `login_alert`, `magic_link`

### Built-in SMS template names

`password_reset`, `phone_verification`, `two_factor_code`, `login_alert`

Use `notification.DefaultEmailTemplates()` or `notification.DefaultSMSTemplates()` to get the full default maps as a starting point.

## Event Hooks

The module subscribes to Core events via `RegisterHooks`. Each hook is controlled by a config flag.

| Event | Action | Config Flag |
|-------|--------|-------------|
| `EventAfterSignup` | Welcome email | `EnableWelcomeEmail` |
| `EventSendEmailVerification` | Email verification delivery | Always enabled |
| `EventSendPhoneVerification` | Phone verification SMS | `Enable2FANotifications` |
| `EventSendPasswordResetEmail` | Password reset email/SMS | `EnablePasswordResetEmail` or `EnablePasswordResetSMS` |
| `EventAfterChangePassword` | Password changed alert | `EnablePasswordChangeAlert` |
| `EventAfterResetPassword` | Password changed alert | `EnablePasswordChangeAlert` |
| `EventSendMagicLink` | Magic link email | `EnableMagicLinkEmail` |
| `EventAfterLogin` | Login alert | `EnableLoginAlerts` |

## Sender Interfaces

Implement these to plug in a custom email or SMS provider:

```go
type EmailSender interface {
    SendEmail(ctx context.Context, message *notification.EmailMessage) error
    VerifyConfig(ctx context.Context) error
}

type SMSSender interface {
    SendSMS(ctx context.Context, message *notification.SMSMessage) error
    VerifyConfig(ctx context.Context) error
}
```

## Testing

Use [Mailtrap](https://mailtrap.io/) or [Ethereal](https://ethereal.email/) for development:

```go
emailSender := senders.NewSMTPEmailSender(&senders.SMTPConfig{
    Host:     "smtp.ethereal.email",
    Port:     587,
    Username: "your-ethereal-username",
    Password: "your-ethereal-password",
})
```

## Extensibility

### Writing a Custom Email Sender

Implement the `EmailSender` interface to integrate any email provider:

```go
type MyEmailSender struct {
    apiKey string
}

func (s *MyEmailSender) SendEmail(ctx context.Context, msg *notification.EmailMessage) error {
    // msg.To, msg.Subject, msg.HTMLBody, msg.TextBody, msg.From, msg.FromName
    // Send via your provider's API
    return nil
}

func (s *MyEmailSender) VerifyConfig(ctx context.Context) error {
    // Validate API key, check connectivity, etc.
    // Called during module initialization
    return nil
}
```

### Writing a Custom SMS Sender

Implement the `SMSSender` interface to integrate any SMS provider:

```go
type MySMSSender struct {
    apiKey string
}

func (s *MySMSSender) SendSMS(ctx context.Context, msg *notification.SMSMessage) error {
    // msg.To, msg.Body, msg.From
    // Send via your provider's API
    return nil
}

func (s *MySMSSender) VerifyConfig(ctx context.Context) error {
    // Validate credentials at init time
    return nil
}
```

### Async Event Processing

Notification delivery is processed asynchronously via the event system. By default, GoAuth uses an in-memory worker pool (10 workers, 1000 queue size). For production environments that require durability or distributed processing, implement the `types.AsyncBackend` interface to use Kafka, NATS, Redis Streams, RabbitMQ, or any message broker. See the [Enterprise](../enterprise.md) page for details.

## Next Steps

- [Core Module](core.md) -- Core auth features
- [API Reference](/docs/api/endpoints) -- All endpoints
