package dto

import (
	"fmt"
	"regexp"
	"strings"
)

// SendVerificationEmailRequest represents email verification request
type SendVerificationEmailRequest struct {
	Email string `json:"email"`
}

func (r *SendVerificationEmailRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	if !isValidEmail(r.Email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// SendVerificationPhoneRequest represents phone verification request
type SendVerificationPhoneRequest struct {
	PhoneNumber string `json:"phone_number"`
}

func (r *SendVerificationPhoneRequest) Validate() error {
	if r.PhoneNumber == "" {
		return fmt.Errorf("phone number is required")
	}
	if !isValidPhoneNumber(r.PhoneNumber) {
		return fmt.Errorf("invalid phone number format")
	}
	return nil
}

// ForgotPasswordRequest represents password reset request
type ForgotPasswordRequest struct {
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}

func (r *ForgotPasswordRequest) Validate() error {
	if r.Email == "" && r.Phone == "" {
		return fmt.Errorf("email or phone is required")
	}
	if r.Email != "" && !isValidEmail(r.Email) {
		return fmt.Errorf("invalid email format")
	}
	if r.Phone != "" && !isValidPhoneNumber(r.Phone) {
		return fmt.Errorf("invalid phone number format")
	}
	return nil
}

// Email regex pattern
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// Phone regex pattern (basic international format)
var phoneRegex = regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)

func isValidEmail(email string) bool {
	email = strings.TrimSpace(email)
	if len(email) > 254 {
		return false
	}
	return emailRegex.MatchString(email)
}

// VerifyEmailRequest represents email verification with token
type VerifyEmailRequest struct {
	Token string `json:"token"`
	Email string `json:"email"`
}

func (r *VerifyEmailRequest) Validate() error {
	if r.Token == "" {
		return fmt.Errorf("token is required")
	}
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	if !isValidEmail(r.Email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// VerifyPhoneRequest represents phone verification with code
type VerifyPhoneRequest struct {
	Code        string `json:"code"`
	PhoneNumber string `json:"phone_number"`
}

func (r *VerifyPhoneRequest) Validate() error {
	if r.Code == "" {
		return fmt.Errorf("code is required")
	}
	if r.PhoneNumber == "" {
		return fmt.Errorf("phone number is required")
	}
	if !isValidPhoneNumber(r.PhoneNumber) {
		return fmt.Errorf("invalid phone number format")
	}
	return nil
}

func isValidPhoneNumber(phone string) bool {
	phone = strings.TrimSpace(phone)
	return phoneRegex.MatchString(phone)
}
