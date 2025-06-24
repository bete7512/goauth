// captcha/cloudflare.go
package recaptcha

import (
	"context"

	"github.com/bete7512/goauth/internal/external"
	"github.com/bete7512/goauth/internal/logger"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type cloudflareVerifier struct {
	Secret string
	Url    string
}

type cloudflareResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes,omitempty"`
}

func NewCloudflareVerifier(secret string, url string) interfaces.CaptchaVerifier {
	return &cloudflareVerifier{
		Secret: secret,
		Url:    url,
	}
}

func (c *cloudflareVerifier) Verify(ctx context.Context, token string, remoteIP string) (bool, error) {
	data := map[string]string{
		"secret":   c.Secret,
		"response": token,
		"remoteip": remoteIP,
	}

	var resp interface{}
	client := external.NewAPIClient(utils.GetBaseURL(c.Url), nil)

	err := client.Post(ctx, utils.GetEndpoint(c.Url), data, &resp)
	if err != nil {
		return false, err
	}
	if resp.(cloudflareResponse).ErrorCodes != nil {
		logger.Errorf("Failed to verify recaptcha: %v", resp.(cloudflareResponse).ErrorCodes)
		return false, nil
	}
	if resp.(cloudflareResponse).Success {
		return true, nil
	}
	return false, nil
}
