package recaptcha

import (
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

func NewRecaptchaVerifier(conf config.RecaptchaConfig) interfaces.CaptchaVerifier {
	switch conf.Provider {
	case config.RecaptchaGoogle:
		return NewGoogleVerifier(conf.SecretKey, conf.APIURL)
	case config.RecaptchaCloudflare:
		return NewCloudflareVerifier(conf.SecretKey, conf.APIURL)
	default:
		return nil
	}
}
