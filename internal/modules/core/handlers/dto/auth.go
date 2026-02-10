package dto

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// SignupRequest represents signup request
type SignupRequest struct {
	Name               string               `json:"name,omitempty"`
	FirstName          string               `json:"first_name,omitempty"`
	LastName           string               `json:"last_name,omitempty"`
	PhoneNumber        string               `json:"phone_number,omitempty"`
	Email              string               `json:"email"`
	Username           string               `json:"username,omitempty"`
	Password           string               `json:"password"`
	ExtendedAttributes []ExtendedAttributes `json:"extended_attributes,omitempty"`
}

func (r *SignupRequest) Validate() error {
	if r.Email == "" && r.Username == "" {
		return fmt.Errorf("email or username is required")
	}
	if r.Email != "" && !isValidEmail(r.Email) {
		return fmt.Errorf("invalid email format")
	}
	if r.Username != "" && !isValidUsername(r.Username) {
		return fmt.Errorf("username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens")
	}
	if r.PhoneNumber != "" && !isValidPhone(r.PhoneNumber) {
		return fmt.Errorf("invalid phone number format (use E.164 format: +1234567890)")
	}

	return nil
}
func (r *SignupRequest) ValidatePassword(policy types.PasswordPolicy) error {
	if r.Password == "" {
		return fmt.Errorf("password is required")
	}
	if len(r.Password) < policy.MinLength {
		return fmt.Errorf("password must be at least %d characters", policy.MinLength)
	}
	if len(r.Password) > policy.MaxLength {
		return fmt.Errorf("password must be less than %d characters", policy.MaxLength)
	}
	if policy.RequireUppercase && !strings.ContainsAny(r.Password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if policy.RequireLowercase && !strings.ContainsAny(r.Password, "abcdefghijklmnopqrstuvwxyz") {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if policy.RequireNumbers && !strings.ContainsAny(r.Password, "0123456789") {
		return fmt.Errorf("password must contain at least one number")
	}
	if policy.RequireSpecial && !strings.ContainsAny(r.Password, "!@#$%^&*()_+-=[]{}|;:,.<>?") {
		return fmt.Errorf("password must contain at least one special character")
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

// RefreshRequest represents token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (r *RefreshRequest) Validate() error {
	if r.RefreshToken == "" {
		return fmt.Errorf("refresh_token is required")
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

// CheckAvailabilityRequest represents availability check request.
// Exactly one of email, username, or phone must be provided.
type CheckAvailabilityRequest struct {
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
	Phone    string `json:"phone,omitempty"`
}

func (r *CheckAvailabilityRequest) Validate() error {
	set := 0
	if r.Email != "" {
		set++
	}
	if r.Username != "" {
		set++
	}
	if r.Phone != "" {
		set++
	}
	if set == 0 {
		return fmt.Errorf("email, username, or phone is required")
	}
	if set > 1 {
		return fmt.Errorf("only one of email, username, or phone should be provided")
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
	AccessToken  *string  `json:"access_token,omitempty"`
	RefreshToken *string  `json:"refresh_token,omitempty"`
	User         *UserDTO `json:"user"`
	ExpiresIn    int64    `json:"expires_in,omitempty"`
	Message      string   `json:"message,omitempty"`
}
type ExtendedAttributes struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// UserDTO represents user data in responses
type UserDTO struct {
	ID                  string               `json:"id"`
	FirstName           string               `json:"first_name,omitempty"`
	LastName            string               `json:"last_name,omitempty"`
	Name                string               `json:"name,omitempty"`
	Email               string               `json:"email"`
	Username            string               `json:"username,omitempty"`
	Avatar              string               `json:"avatar,omitempty"`
	PhoneNumber         string               `json:"phone_number,omitempty"`
	Active              bool                 `json:"active"`
	EmailVerified       bool                 `json:"email_verified"`
	PhoneNumberVerified bool                 `json:"phone_number_verified"`
	CreatedAt           time.Time            `json:"created_at"`
	UpdatedAt           *time.Time           `json:"updated_at"`
	LastLoginAt         *time.Time           `json:"last_login_at,omitempty"`
	ExtendedAttributes  []ExtendedAttributes `json:"extended_attributes,omitempty"`
}

func (u *UserDTO) ToUser() *models.User {
	return &models.User{
		ID:                  u.ID,
		FirstName:           u.FirstName,
		LastName:            u.LastName,
		Name:                u.Name,
		Email:               u.Email,
		Username:            u.Username,
		Avatar:              u.Avatar,
		PhoneNumber:         u.PhoneNumber,
		Active:              u.Active,
		EmailVerified:       u.EmailVerified,
		PhoneNumberVerified: u.PhoneNumberVerified,
		CreatedAt:           u.CreatedAt,
		UpdatedAt:           u.UpdatedAt,
		LastLoginAt:         u.LastLoginAt,
		ExtendedAttributes: func() []models.ExtendedAttributes {
			attrs := make([]models.ExtendedAttributes, len(u.ExtendedAttributes))
			for i, attr := range u.ExtendedAttributes {
				attrs[i] = models.ExtendedAttributes{Name: attr.Name, Value: attr.Value}
			}
			return attrs
		}(),
	}
}

func (u *UserDTO) ToUserDTO() *UserDTO {
	return &UserDTO{
		ID:                  u.ID,
		FirstName:           u.FirstName,
		LastName:            u.LastName,
		Name:                u.Name,
		Email:               u.Email,
		Username:            u.Username,
		Avatar:              u.Avatar,
		PhoneNumber:         u.PhoneNumber,
		Active:              u.Active,
		EmailVerified:       u.EmailVerified,
		PhoneNumberVerified: u.PhoneNumberVerified,
		CreatedAt:           u.CreatedAt,
		UpdatedAt:           u.UpdatedAt,
		LastLoginAt:         u.LastLoginAt,
		ExtendedAttributes:  u.ExtendedAttributes,
	}
}

// MessageResponse represents a simple message response
type MessageResponse struct {
	Message string `json:"message"`
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
