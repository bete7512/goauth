package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	googleVerifyURL     = "https://www.google.com/recaptcha/api/siteverify"
	cloudflareVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	defaultTimeout      = 10 * time.Second
	defaultThreshold    = 0.5
)

// CaptchaProvider verifies a captcha token with an external provider.
type CaptchaProvider interface {
	Verify(ctx context.Context, token, remoteIP string) (bool, error)
}

// CaptchaService delegates captcha verification to the configured provider.
type CaptchaService struct {
	provider CaptchaProvider
}

// NewCaptchaService creates a captcha service with the given provider.
// If provider is nil, Verify will always return an error.
func NewCaptchaService(provider CaptchaProvider) *CaptchaService {
	return &CaptchaService{provider: provider}
}

// Verify delegates to the configured provider.
func (s *CaptchaService) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	if s.provider == nil {
		return false, fmt.Errorf("captcha: no provider configured")
	}
	return s.provider.Verify(ctx, token, remoteIP)
}

// Provider returns the configured provider (may be nil).
func (s *CaptchaService) Provider() CaptchaProvider {
	return s.provider
}

// GoogleProvider implements Google reCAPTCHA v3 verification.
type GoogleProvider struct {
	secretKey string
	threshold float64
	client    *http.Client
	verifyURL string // overridable for testing
}

// NewGoogleProvider creates a Google reCAPTCHA v3 provider.
func NewGoogleProvider(secretKey string, threshold float64, timeout time.Duration) *GoogleProvider {
	if threshold <= 0 {
		threshold = defaultThreshold
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &GoogleProvider{
		secretKey: secretKey,
		threshold: threshold,
		client:    &http.Client{Timeout: timeout},
		verifyURL: googleVerifyURL,
	}
}

type recaptchaResponse struct {
	Success    bool     `json:"success"`
	Score      float64  `json:"score"`
	Action     string   `json:"action"`
	Hostname   string   `json:"hostname"`
	ErrorCodes []string `json:"error-codes"`
}

func (p *GoogleProvider) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	form := url.Values{
		"secret":   {p.secretKey},
		"response": {token},
		"remoteip": {remoteIP},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.verifyURL, nil)
	if err != nil {
		return false, fmt.Errorf("captcha: failed to create request: %w", err)
	}
	req.URL.RawQuery = form.Encode()

	resp, err := p.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("captcha: google verification request failed: %w", err)
	}
	defer resp.Body.Close()

	var result recaptchaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("captcha: failed to decode google response: %w", err)
	}

	if !result.Success {
		return false, fmt.Errorf("captcha: google verification failed: %v", result.ErrorCodes)
	}

	if result.Score < p.threshold {
		return false, nil
	}

	return true, nil
}

// SetVerifyURL overrides the verification endpoint (for testing).
func (p *GoogleProvider) SetVerifyURL(url string) { p.verifyURL = url }

// CloudflareProvider implements Cloudflare Turnstile verification.
type CloudflareProvider struct {
	secretKey string
	client    *http.Client
	verifyURL string // overridable for testing
}

// NewCloudflareProvider creates a Cloudflare Turnstile provider.
func NewCloudflareProvider(secretKey string, timeout time.Duration) *CloudflareProvider {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &CloudflareProvider{
		secretKey: secretKey,
		client:    &http.Client{Timeout: timeout},
		verifyURL: cloudflareVerifyURL,
	}
}

type turnstileResponse struct {
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
	ErrorCodes []string `json:"error-codes"`
	Action     string   `json:"action"`
	CData      string   `json:"cdata"`
}

func (p *CloudflareProvider) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	form := url.Values{
		"secret":   {p.secretKey},
		"response": {token},
		"remoteip": {remoteIP},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.verifyURL, nil)
	if err != nil {
		return false, fmt.Errorf("captcha: failed to create request: %w", err)
	}
	req.URL.RawQuery = form.Encode()

	resp, err := p.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("captcha: cloudflare verification request failed: %w", err)
	}
	defer resp.Body.Close()

	var result turnstileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("captcha: failed to decode cloudflare response: %w", err)
	}

	if !result.Success {
		return false, fmt.Errorf("captcha: cloudflare verification failed: %v", result.ErrorCodes)
	}

	return true, nil
}

// SetVerifyURL overrides the verification endpoint (for testing).
func (p *CloudflareProvider) SetVerifyURL(url string) { p.verifyURL = url }
