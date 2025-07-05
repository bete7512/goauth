package config

import "time"

type SecurityConfig struct {
	RateLimiter RateLimiterConfig
	Recaptcha   RecaptchaConfig
	CSRF        CSRFConfig
}

type RateLimiterConfig struct {
	Enabled bool
	Routes  map[string]LimiterConfig
}

type RecaptchaConfig struct {
	Enabled   bool
	SecretKey string
	SiteKey   string
	Provider  RecaptchaProvider
	APIURL    string
	Routes    map[string]bool
}

type LimiterConfig struct {
	WindowSize    time.Duration
	MaxRequests   int
	BlockDuration time.Duration
}

// CSRFConfig configuration for CSRF protection
type CSRFConfig struct {
	TokenLength   int
	TokenTTL      time.Duration
	Routes        map[string]bool
	CookieEnabled bool
	CookieConfig  CookieConfig
}
