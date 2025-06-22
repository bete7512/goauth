package recaptcha

import "github.com/bete7512/goauth/config"

func NewRecaptchaVerifier(config config.RecaptchaConfig) config.CaptchaVerifier {
	switch config.Provider {
	case "google":
		return NewGoogleVerifier(config.SecretKey, config.APIURL)
	case "cloudflare":
		return NewCloudflareVerifier(config.SecretKey, config.APIURL)
	default:
		return nil
	}
}
