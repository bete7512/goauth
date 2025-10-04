package senders

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/notification/models"
)

// ResendEmailSender implements EmailSender using Resend
type ResendEmailSender struct {
	apiKey          string
	client          *http.Client
	baseURL         string
	defaultFrom     string
	defaultFromName string
}

// ResendConfig holds Resend configuration
type ResendConfig struct {
	APIKey          string
	DefaultFrom     string
	DefaultFromName string
}

// resendRequest represents the Resend API request
type resendRequest struct {
	From        string             `json:"from"`
	To          []string           `json:"to"`
	Subject     string             `json:"subject"`
	Text        string             `json:"text,omitempty"`
	HTML        string             `json:"html,omitempty"`
	CC          []string           `json:"cc,omitempty"`
	BCC         []string           `json:"bcc,omitempty"`
	ReplyTo     string             `json:"reply_to,omitempty"`
	Attachments []resendAttachment `json:"attachments,omitempty"`
}

type resendAttachment struct {
	Filename string `json:"filename"`
	Content  string `json:"content"` // Base64 encoded
}

// NewResendEmailSender creates a new Resend email sender
func NewResendEmailSender(config *ResendConfig) *ResendEmailSender {
	return &ResendEmailSender{
		apiKey:          config.APIKey,
		client:          &http.Client{},
		baseURL:         "https://api.resend.com",
		defaultFrom:     config.DefaultFrom,
		defaultFromName: config.DefaultFromName,
	}
}

// SendEmail sends an email using Resend
func (r *ResendEmailSender) SendEmail(ctx context.Context, message *models.EmailMessage) error {
	from := message.From
	if from == "" {
		from = r.defaultFrom
	}
	if message.FromName != "" {
		from = fmt.Sprintf("%s <%s>", message.FromName, from)
	} else if r.defaultFromName != "" {
		from = fmt.Sprintf("%s <%s>", r.defaultFromName, from)
	}

	req := resendRequest{
		From:    from,
		To:      message.To,
		Subject: message.Subject,
		Text:    message.TextBody,
		HTML:    message.HTMLBody,
		CC:      message.CC,
		BCC:     message.BCC,
		ReplyTo: message.ReplyTo,
	}

	// Add attachments (base64 encode)
	for _, att := range message.Attachments {
		req.Attachments = append(req.Attachments, resendAttachment{
			Filename: att.Filename,
			Content:  string(att.Content), // Should be base64 encoded
		})
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("resend: failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", r.baseURL+"/emails", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("resend: failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+r.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("resend: failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("resend: server returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// VerifyConnection verifies the Resend API connection
func (r *ResendEmailSender) VerifyConfig(ctx context.Context) error {
	if r.apiKey == "" {
		return fmt.Errorf("resend: API key is required")
	}
	// Resend doesn't have a dedicated ping endpoint
	return nil
}
