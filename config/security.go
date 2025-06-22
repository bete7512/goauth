package config

type SecurityConfig struct {
	RateLimiter RateLimiterConfig
	Recaptcha   RecaptchaConfig
}

type RateLimiterConfig struct {
	Enabled bool
	Type    RateLimiterStorageType
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
