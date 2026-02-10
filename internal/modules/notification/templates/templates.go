package templates

import (
	"embed"
	"fmt"
)

//go:embed html/*.html
var defaultFS embed.FS

// Branding holds the product-specific branding injected into every email template.
// Library consumers configure this once; it flows into every email automatically.
type Branding struct {
	AppName      string // e.g. "Acme Corp" — used in subject lines and headings
	LogoURL      string // absolute URL to product logo (displayed in email header)
	PrimaryColor string // hex color for buttons and header background, e.g. "#007bff"
	TextColor    string // hex color for body text, defaults to "#333333"
	ContactEmail string // support email shown in footer, e.g. "support@acme.com"
	DomainName   string // product domain shown in footer, e.g. "acme.com"
	FooterText   string // custom footer line, e.g. "© 2026 Acme Corp. All rights reserved."
}

// DefaultBranding returns sensible defaults so emails render well even without config.
func DefaultBranding() *Branding {
	return &Branding{
		AppName:      "GoAuth",
		PrimaryColor: "#007bff",
		TextColor:    "#333333",
	}
}

// BrandingData returns branding as a map for template injection.
func (b *Branding) BrandingData() map[string]interface{} {
	if b == nil {
		b = DefaultBranding()
	}
	return map[string]interface{}{
		"AppName":      b.AppName,
		"LogoURL":      b.LogoURL,
		"PrimaryColor": b.PrimaryColor,
		"TextColor":    b.textColor(),
		"ContactEmail": b.ContactEmail,
		"DomainName":   b.DomainName,
		"FooterText":   b.FooterText,
	}
}

func (b *Branding) textColor() string {
	if b.TextColor == "" {
		return "#333333"
	}
	return b.TextColor
}

// EmailTemplate represents an email notification template.
type EmailTemplate struct {
	Name     string
	Subject  string // Go template string
	TextBody string // Go template string (plain text fallback)
	HTMLBody string // Go template string (loaded from FS or set directly)
}

// SMSTemplate represents an SMS notification template.
type SMSTemplate struct {
	Name string
	Body string // Go template string
}

// loadHTML reads an HTML file from the given filesystem.
func loadHTML(name string) string {
	data, err := defaultFS.ReadFile("html/" + name + ".html")
	if err != nil {
		panic(fmt.Sprintf("notification: missing template html/%s.html: %v", name, err))
	}
	return string(data)
}

// LoadBaseHTML reads the base layout from the given filesystem.
func LoadBaseHTML() string {
	return loadHTML("base")
}

// DefaultEmailTemplates builds the default email template map from the given FS.
// Pass defaultFS for built-in templates, or a custom fs.FS to override.
func DefaultEmailTemplates() map[string]EmailTemplate {
	return map[string]EmailTemplate{
		"welcome": {
			Name:     "welcome",
			Subject:  "Welcome to {{.Brand.AppName}}!",
			TextBody: "Hi {{.UserName}},\n\nWelcome to {{.Brand.AppName}}! Your account has been created successfully.\n\n{{.Brand.FooterText}}",
			HTMLBody: loadHTML("welcome"),
		},
		"password_reset": {
			Name:     "password_reset",
			Subject:  "Password Reset Request - {{.Brand.AppName}}",
			TextBody: "Hi {{.UserName}},\n\nClick here to reset your password: {{.ResetLink}}\n\nOr use this code: {{.Code}}\n\nThis link expires in {{.ExpiryTime}}.\n\n{{.Brand.FooterText}}",
			HTMLBody: loadHTML("password_reset"),
		},
		"email_verification": {
			Name:     "email_verification",
			Subject:  "Verify Your Email - {{.Brand.AppName}}",
			TextBody: "Hi {{.UserName}},\n\nPlease verify your email by clicking: {{.VerificationLink}}\n\n{{.Brand.FooterText}}",
			HTMLBody: loadHTML("email_verification"),
		},
		"two_factor_code": {
			Name:     "two_factor_code",
			Subject:  "Your 2FA Code - {{.Brand.AppName}}",
			TextBody: "Your 2FA code is: {{.Code}}. Valid for {{.ExpiryTime}}.\n\n{{.Brand.FooterText}}",
			HTMLBody: loadHTML("two_factor_code"),
		},
		"login_alert": {
			Name:     "login_alert",
			Subject:  "New Login Detected - {{.Brand.AppName}}",
			TextBody: "Hi {{.UserName}},\n\nA new login was detected from {{.IPAddress}} at {{.Timestamp}}.\n\n{{.Brand.FooterText}}",
			HTMLBody: loadHTML("login_alert"),
		},
		"password_changed": {
			Name:     "password_changed",
			Subject:  "Your Password Has Been Changed - {{.Brand.AppName}}",
			TextBody: "Hi {{.UserName}},\n\nYour password was changed at {{.Timestamp}}. If this wasn't you, contact support at {{.Brand.ContactEmail}} immediately.\n\n{{.Brand.FooterText}}",
			HTMLBody: loadHTML("password_changed"),
		},
	}
}

// DefaultSMSTemplates returns the default SMS template map.
func DefaultSMSTemplates() map[string]SMSTemplate {
	return map[string]SMSTemplate{
		"password_reset": {
			Name: "password_reset",
			Body: "{{.Brand.AppName}}: Your password reset code is {{.Code}}. Valid for {{.ExpiryTime}}.",
		},
		"phone_verification": {
			Name: "phone_verification",
			Body: "{{.Brand.AppName}}: Your verification code is {{.Code}}. Valid for {{.ExpiryTime}}.",
		},
		"two_factor_code": {
			Name: "two_factor_code",
			Body: "{{.Brand.AppName}}: Your 2FA code is {{.Code}}. Valid for {{.ExpiryTime}}.",
		},
		"login_alert": {
			Name: "login_alert",
			Body: "{{.Brand.AppName}}: New login from {{.IPAddress}} at {{.Timestamp}}.",
		},
	}
}
