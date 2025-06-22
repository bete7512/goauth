package sms

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bete7512/goauth/config"
	"github.com/bete7512/goauth/models"
)

type SMSSender struct {
	config     config.SMSConfig
	httpClient *http.Client
}

// SendMagicLink implements types.SMSSenderInterface.
func (s *SMSSender) SendMagicLink(user models.User, redirectURL string) error {
	panic("unimplemented")
}

func NewSMSSender(config config.SMSConfig) *SMSSender {
	return &SMSSender{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (s *SMSSender) SendTwoFactorCode(user models.User, code string) error {
	if user.PhoneNumber == nil {
		return fmt.Errorf("user phone number is nil")
	}
	message := fmt.Sprintf("Your %s verification code is: %s. Valid for 10 minutes.", s.config.CompanyName, code)
	return s.sendSMS(*user.PhoneNumber, message)
}

func (s *SMSSender) SendVerificationCode(user models.User, code string) error {
	if user.PhoneNumber == nil {
		return fmt.Errorf("user phone number is nil")
	}
	message := fmt.Sprintf("Your %s verification code is: %s. Valid for 10 minutes.", s.config.CompanyName, code)
	return s.sendSMS(*user.PhoneNumber, message)
}

func (s *SMSSender) SendWelcome(user models.User) error {
	if user.PhoneNumber == nil {
		return fmt.Errorf("user phone number is nil")
	}
	message := fmt.Sprintf("Welcome to %s! Your account has been successfully created.", s.config.CompanyName)
	return s.sendSMS(*user.PhoneNumber, message)
}

func (s *SMSSender) sendSMS(to, message string) error {
	// If custom SMS sender is provided, use it
	if s.config.CustomSender != nil {
		// Create a temporary user for the interface method
		tempUser := models.User{PhoneNumber: &to}
		return s.config.CustomSender.SendVerificationCode(tempUser, message)
	}

	// Use Twilio as default
	return s.sendViaTwilio(to, message)
}

func (s *SMSSender) sendViaTwilio(to, message string) error {
	// Twilio API request
	data := url.Values{}
	data.Set("To", to)
	data.Set("From", s.config.Twilio.FromNumber)
	data.Set("Body", message)

	req, err := http.NewRequest("POST", "https://api.twilio.com/2010-04-01/Accounts/"+s.config.Twilio.AccountSID+"/Messages.json", strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(s.config.Twilio.AccountSID, s.config.Twilio.AuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send SMS: %w", err)
	}
	defer resp.Body.Close()
	j, _ := io.ReadAll(resp.Body)
	log.Println(">>>>>>>>>>>>>>", string(j))
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("twilio API error: %d", resp.StatusCode)
	}

	return nil
}
