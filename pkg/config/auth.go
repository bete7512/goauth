package config

import (
	"net/http"
	"time"

	"github.com/bete7512/goauth/pkg/interfaces"
)

type AuthConfig struct {
	// JWT settings
	JWT JWTConfig

	// Token TTLs
	Tokens TokenConfig

	// Authentication methods
	Methods AuthMethodsConfig

	// Policies
	PasswordPolicy PasswordPolicy
	Cookie         CookieConfig

	// Email verification
	BlockedEmailDomains []string
	AllowedEmailDomains []string
}

type JWTConfig struct {
	Secret          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	// Custom claims
	EnableCustomClaims bool
	ClaimsProvider     interfaces.CustomJWTClaimsProvider
}

type TokenConfig struct {
	HashSaltLength       int
	PhoneVerificationTTL time.Duration
	EmailVerificationTTL time.Duration
	PasswordResetTTL     time.Duration
	TwoFactorTTL         time.Duration
	MagicLinkTTL         time.Duration
}

type AuthMethodsConfig struct {
	Type                  AuthenticationType
	EnableTwoFactor       bool
	EnableMultiSession    bool
	EnableMagicLink       bool
	EnableSmsVerification bool
	TwoFactorMethod       string

	// Verification settings
	EmailVerification EmailVerificationConfig
	PhoneVerification PhoneVerificationConfig
}

type EmailVerificationConfig struct {
	EnableOnSignup   bool
	VerificationURL  string
	SendWelcomeEmail bool
}

type PhoneVerificationConfig struct {
	EnableOnSignup      bool
	UniquePhoneNumber   bool
	PhoneColumnRequired bool
	PhoneRequired       bool
}

type PasswordPolicy struct {
	HashSaltLength int
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
}

type CookieConfig struct {
	Name     string
	Secure   bool
	HttpOnly bool
	Domain   string
	Path     string
	MaxAge   int
	SameSite http.SameSite
}

type RouteInfo struct {
	Method  string
	Path    string
	Name    string
	Handler http.HandlerFunc
}
