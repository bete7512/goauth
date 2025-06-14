package recaptcha

import (
	"context"

	"github.com/bete7512/goauth/external"
	"github.com/bete7512/goauth/logger"
	"github.com/bete7512/goauth/types"
	"github.com/bete7512/goauth/utils"
)

type googleVerifier struct {
	Secret string
	Url    string
}

type googleResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes,omitempty"`
}

func NewGoogleVerifier(secret string, url string) types.CaptchaVerifier {
	return &googleVerifier{
		Secret: secret,
		Url:    url,
	}
}

func (g *googleVerifier) Verify(token string, remoteIP string) (bool, error) {
	data := map[string]string{
		"secret":   g.Secret,
		"response": token,
		"remoteip": remoteIP,
	}

	client := external.NewAPIClient(utils.GetBaseURL(g.Url), nil)
	var resp interface{}
	err := client.Post(context.Background(), utils.GetEndpoint(g.Url), data, &resp)
	if err != nil {
		logger.Errorf("Failed to verify recaptcha: %v", err)
		return false, err
	}
	if resp.(googleResponse).ErrorCodes != nil {
		logger.Errorf("Failed to verify recaptcha: %v", resp.(googleResponse).ErrorCodes)
		return false, nil
	}
	if resp.(googleResponse).Success {
		return true, nil
	}
	return false, nil
}
