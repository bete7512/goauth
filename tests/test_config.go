package tests

import (
	"time"

	"github.com/bete7512/goauth/pkg/config"
)

// GetTestConfig returns a test configuration
func GetTestConfig() config.Config {
	return config.Config{
		App: config.AppConfig{
			BasePath:    "/auth",
			Domain:      "localhost",
			FrontendURL: "http://localhost:3000",
		},
		Database: config.DatabaseConfig{
			Type: "sqlite",
			URL:  ":memory:", // Use in-memory SQLite for tests
		},
		AuthConfig: config.AuthConfig{
			JWT: config.JWTConfig{
				Secret:             "test-secret-key-32-chars-long",
				AccessTokenTTL:     15 * time.Minute,
				RefreshTokenTTL:    7 * 24 * time.Hour,
				EnableCustomClaims: false,
			},
			Tokens: config.TokenConfig{
				HashSaltLength:       16,
				PhoneVerificationTTL: 10 * time.Minute,
				EmailVerificationTTL: 1 * time.Hour,
				PasswordResetTTL:     10 * time.Minute,
				TwoFactorTTL:         10 * time.Minute,
				MagicLinkTTL:         10 * time.Minute,
			},
			Methods: config.AuthMethodsConfig{
				Type:                  config.AuthenticationTypeCookie,
				EnableTwoFactor:       false,
				EnableMultiSession:    false,
				EnableMagicLink:       false,
				EnableSmsVerification: false,
				TwoFactorMethod:       "email",
				EmailVerification: config.EmailVerificationConfig{
					EnableOnSignup:   false,
					VerificationURL:  "http://localhost:3000/verify",
					SendWelcomeEmail: false,
				},
			},
			PasswordPolicy: config.PasswordPolicy{
				HashSaltLength: 16,
				MinLength:      8,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumber:  true,
				RequireSpecial: false,
			},
			Cookie: config.CookieConfig{
				Name:     "auth_token",
				Path:     "/",
				MaxAge:   86400,
				Secure:   false,
				HttpOnly: true,
				SameSite: 1,
			},
		},
		Features: config.FeaturesConfig{
			EnableRateLimiter:   false,
			EnableRecaptcha:     false,
			EnableCustomJWT:     false,
			EnableCustomStorage: false,
		},
		Security: config.SecurityConfig{
			RateLimiter: config.RateLimiterConfig{
				Enabled: false,
				Type:    config.MemoryRateLimiter,
				Routes:  make(map[string]config.LimiterConfig),
			},
			Recaptcha: config.RecaptchaConfig{
				Enabled:   false,
				SecretKey: "",
				SiteKey:   "",
				Provider:  "google",
				APIURL:    "",
				Routes:    make(map[string]bool),
			},
		},
		Email: config.EmailConfig{
			Sender: config.EmailSenderConfig{
				Type:         config.SendGrid,
				FromEmail:    "test@example.com",
				FromName:     "Test App",
				SupportEmail: "support@example.com",
				CustomSender: nil,
			},
		},
		SMS: config.SMSConfig{
			CompanyName:  "Test Company",
			CustomSender: nil,
		},
		Providers: config.ProvidersConfig{
			Enabled: []config.AuthProvider{},
		},
	}
}
