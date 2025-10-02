package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// CaptchaService manages captcha verification
type CaptchaService struct {
	provider CaptchaProvider
}

// CaptchaProvider interface for different captcha providers
type CaptchaProvider interface {
	Verify(ctx context.Context, token, remoteIP string) (bool, error)
}

func NewCaptchaService() *CaptchaService {
	return &CaptchaService{}
}

func (s *CaptchaService) SetProvider(provider CaptchaProvider) {
	s.provider = provider
}

func (s *CaptchaService) GetProvider() CaptchaProvider {
	return s.provider
}

// Verify verifies a captcha token using the configured provider
func (s *CaptchaService) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	if s.provider == nil {
		return false, fmt.Errorf("no captcha provider configured")
	}
	return s.provider.Verify(ctx, token, remoteIP)
}

// GoogleRecaptchaProvider implements Google reCAPTCHA v3 verification
type GoogleRecaptchaProvider struct {
	SecretKey string
	Threshold float64
}

type recaptchaResponse struct {
	Success     bool      `json:"success"`
	Score       float64   `json:"score"`
	Action      string    `json:"action"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

func (p *GoogleRecaptchaProvider) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	reqBody, err := json.Marshal(map[string]string{
		"secret":   p.SecretKey,
		"response": token,
		"remoteip": remoteIP,
	})
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://www.google.com/recaptcha/api/siteverify",
		bytes.NewBuffer(reqBody))
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result recaptchaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	if !result.Success {
		return false, fmt.Errorf("recaptcha verification failed: %v", result.ErrorCodes)
	}

	// Check score against threshold
	return result.Score >= p.Threshold, nil
}

// CloudflareTurnstileProvider implements Cloudflare Turnstile verification
type CloudflareTurnstileProvider struct {
	SecretKey string
}

type turnstileResponse struct {
	Success     bool      `json:"success"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
	Action      string    `json:"action"`
	CData       string    `json:"cdata"`
}

func (p *CloudflareTurnstileProvider) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	reqBody, err := json.Marshal(map[string]string{
		"secret":   p.SecretKey,
		"response": token,
		"remoteip": remoteIP,
	})
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://challenges.cloudflare.com/turnstile/v0/siteverify",
		bytes.NewBuffer(reqBody))
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result turnstileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	if !result.Success {
		return false, fmt.Errorf("turnstile verification failed: %v", result.ErrorCodes)
	}

	return true, nil
}
