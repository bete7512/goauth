package recaptcha

import (
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

func NewRecaptchaVerifier(config config.RecaptchaConfig) interfaces.CaptchaVerifier {
	switch config.Provider {
	case "google":
		return NewGoogleVerifier(config.SecretKey, config.APIURL)
	case "cloudflare":
		return NewCloudflareVerifier(config.SecretKey, config.APIURL)
	default:
		return nil
	}
}
