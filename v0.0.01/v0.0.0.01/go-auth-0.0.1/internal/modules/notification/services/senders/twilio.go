package senders

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/bete7512/goauth/internal/modules/notification/models"
)

// TwilioSMSSender implements SMSSender using Twilio
type TwilioSMSSender struct {
	accountSID string
	authToken  string
	fromNumber string
	client     *http.Client
	baseURL    string
}

// TwilioConfig holds Twilio configuration
type TwilioConfig struct {
	AccountSID string
	AuthToken  string
	FromNumber string // Your Twilio phone number
}

// NewTwilioSMSSender creates a new Twilio SMS sender
func NewTwilioSMSSender(config *TwilioConfig) *TwilioSMSSender {
	return &TwilioSMSSender{
		accountSID: config.AccountSID,
		authToken:  config.AuthToken,
		fromNumber: config.FromNumber,
		client:     &http.Client{},
		baseURL:    "https://api.twilio.com/2010-04-01",
	}
}

// SendSMS sends an SMS using Twilio
func (t *TwilioSMSSender) SendSMS(ctx context.Context, message *models.SMSMessage) error {
	from := message.From
	if from == "" {
		from = t.fromNumber
	}

	// Build request
	data := url.Values{}
	data.Set("To", message.To)
	data.Set("From", from)
	data.Set("Body", message.Body)

	// Add media URLs for MMS
	for _, mediaURL := range message.MediaURL {
		data.Add("MediaUrl", mediaURL)
	}

	// Create request
	apiURL := fmt.Sprintf("%s/Accounts/%s/Messages.json", t.baseURL, t.accountSID)
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("twilio: failed to create request: %w", err)
	}

	req.SetBasicAuth(t.accountSID, t.authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("twilio: failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("twilio: server returned status %d", resp.StatusCode)
	}

	return nil
}

// VerifyConnection verifies the Twilio API connection
func (t *TwilioSMSSender) VerifyConnection(ctx context.Context) error {
	if t.accountSID == "" {
		return fmt.Errorf("twilio: account SID is required")
	}
	if t.authToken == "" {
		return fmt.Errorf("twilio: auth token is required")
	}
	if t.fromNumber == "" {
		return fmt.Errorf("twilio: from number is required")
	}
	return nil
}

