package dto

import (
	"fmt"
	"regexp"
	"strings"
)

// SignupRequest represents signup request
type SignupRequest struct {
	Email    string `json:"email"`
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
	Name     string `json:"name,omitempty"`
	Phone    string `json:"phone,omitempty"`
}

func (r *SignupRequest) Validate() error {
	if r.Email == "" && r.Username == "" {
		return fmt.Errorf("email or username is required")
	}
	if r.Email != "" && !isValidEmail(r.Email) {
		return fmt.Errorf("invalid email format")
	}
	if r.Password == "" {
		return fmt.Errorf("password is required")
	}
	if len(r.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if r.Username != "" && !isValidUsername(r.Username) {
		return fmt.Errorf("username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens")
	}
	if r.Phone != "" && !isValidPhone(r.Phone) {
		return fmt.Errorf("invalid phone number format (use E.164 format: +1234567890)")
	}
	return nil
}

// LoginRequest represents login request
type LoginRequest struct {
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
}

func (r *LoginRequest) Validate() error {
	if r.Email == "" && r.Username == "" {
		return fmt.Errorf("email or username is required")
	}
	if r.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}

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

// VerifyEmailRequest represents email verification with token
type VerifyEmailRequest struct {
	Token string `json:"token"`
	Email string `json:"email"`
}

func (r *VerifyEmailRequest) Validate() error {
	if r.Token == "" {
		return fmt.Errorf("verification token is required")
	}
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	return nil
}

// SendVerificationPhoneRequest represents phone verification request
type SendVerificationPhoneRequest struct {
	Phone string `json:"phone"`
}

func (r *SendVerificationPhoneRequest) Validate() error {
	if r.Phone == "" {
		return fmt.Errorf("phone number is required")
	}
	if !isValidPhone(r.Phone) {
		return fmt.Errorf("invalid phone number format (use E.164 format: +1234567890)")
	}
	return nil
}

// VerifyPhoneRequest represents phone verification with OTP
type VerifyPhoneRequest struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

func (r *VerifyPhoneRequest) Validate() error {
	if r.Phone == "" {
		return fmt.Errorf("phone number is required")
	}
	if r.Code == "" {
		return fmt.Errorf("verification code is required")
	}
	if len(r.Code) != 6 {
		return fmt.Errorf("verification code must be 6 digits")
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
	if r.Phone != "" && !isValidPhone(r.Phone) {
		return fmt.Errorf("invalid phone number format")
	}
	return nil
}

// ResetPasswordRequest represents password reset with token/code
type ResetPasswordRequest struct {
	Token       string `json:"token,omitempty"`
	Code        string `json:"code,omitempty"`
	Email       string `json:"email,omitempty"`
	Phone       string `json:"phone,omitempty"`
	NewPassword string `json:"new_password"`
}

func (r *ResetPasswordRequest) Validate() error {
	if r.Token == "" && r.Code == "" {
		return fmt.Errorf("reset token or code is required")
	}
	if r.Email == "" && r.Phone == "" {
		return fmt.Errorf("email or phone is required")
	}
	if r.NewPassword == "" {
		return fmt.Errorf("new password is required")
	}
	if len(r.NewPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	return nil
}

// UpdateProfileRequest represents profile update request
type UpdateProfileRequest struct {
	Name   string `json:"name,omitempty"`
	Phone  string `json:"phone,omitempty"`
	Avatar string `json:"avatar,omitempty"`
}

func (r *UpdateProfileRequest) Validate() error {
	if r.Phone != "" && !isValidPhone(r.Phone) {
		return fmt.Errorf("invalid phone number format")
	}
	if r.Avatar != "" && !isValidURL(r.Avatar) {
		return fmt.Errorf("invalid avatar URL")
	}
	return nil
}

// ChangePasswordRequest represents password change request
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (r *ChangePasswordRequest) Validate() error {
	if r.OldPassword == "" {
		return fmt.Errorf("old password is required")
	}
	if r.NewPassword == "" {
		return fmt.Errorf("new password is required")
	}
	if len(r.NewPassword) < 8 {
		return fmt.Errorf("new password must be at least 8 characters")
	}
	if r.OldPassword == r.NewPassword {
		return fmt.Errorf("new password must be different from old password")
	}
	return nil
}

// CheckAvailabilityRequest represents availability check request
type CheckAvailabilityRequest struct {
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
	Phone    string `json:"phone,omitempty"`
}

func (r *CheckAvailabilityRequest) Validate() error {
	if r.Email == "" && r.Username == "" && r.Phone == "" {
		return fmt.Errorf("at least one field (email, username, or phone) is required")
	}
	if r.Email != "" && !isValidEmail(r.Email) {
		return fmt.Errorf("invalid email format")
	}
	if r.Username != "" && !isValidUsername(r.Username) {
		return fmt.Errorf("invalid username format")
	}
	if r.Phone != "" && !isValidPhone(r.Phone) {
		return fmt.Errorf("invalid phone number format")
	}
	return nil
}

// Response DTOs

// AuthResponse represents authentication response
type AuthResponse struct {
	Token        string   `json:"token,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	User         *UserDTO `json:"user"`
	ExpiresIn    int64    `json:"expires_in,omitempty"`
	Message      string   `json:"message,omitempty"`
}

// UserDTO represents user data in responses
type UserDTO struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Username      string `json:"username,omitempty"`
	Name          string `json:"name,omitempty"`
	Avatar        string `json:"avatar,omitempty"`
	Phone         string `json:"phone,omitempty"`
	Active        bool   `json:"active"`
	EmailVerified bool   `json:"email_verified"`
	PhoneVerified bool   `json:"phone_verified"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// MessageResponse represents a simple message response
type MessageResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code,omitempty"`
}

// CheckAvailabilityResponse represents availability check response
type CheckAvailabilityResponse struct {
	Available bool   `json:"available"`
	Field     string `json:"field"`
	Message   string `json:"message,omitempty"`
}

// Validation helper functions

var (
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,30}$`)
	phoneRegex    = regexp.MustCompile(`^\+[1-9]\d{1,14}$`) // E.164 format
	urlRegex      = regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
)

func isValidEmail(email string) bool {
	email = strings.TrimSpace(email)
	if len(email) > 254 {
		return false
	}
	return emailRegex.MatchString(email)
}

func isValidUsername(username string) bool {
	username = strings.TrimSpace(username)
	return usernameRegex.MatchString(username)
}

func isValidPhone(phone string) bool {
	phone = strings.TrimSpace(phone)
	return phoneRegex.MatchString(phone)
}

func isValidURL(url string) bool {
	url = strings.TrimSpace(url)
	return urlRegex.MatchString(url)
}
