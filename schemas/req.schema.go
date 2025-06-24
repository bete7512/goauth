package schemas

import "time"

type RegisterRequest struct {
	FirstName      string  `json:"first_name" binding:"required"`
	LastName       string  `json:"last_name" binding:"required"`
	Email          string  `json:"email" binding:"required,email"`
	PhoneNumber    *string `json:"phone_number"`
	Password       string  `json:"password" binding:"required,min=8"`
	RecaptchaToken string  `json:"recaptcha_token,omitempty"`
}

// LoginRequest represents the request body for user login
type LoginRequest struct {
	Email          string `json:"email" validate:"required,email"`
	Password       string `json:"password" validate:"required"`
	TwoFactorCode  string `json:"two_factor_code,omitempty"`
	DeviceId       string `json:"device_id,omitempty"`
	RecaptchaToken string `json:"recaptcha_token,omitempty"`
}

// RefreshTokenRequest represents the request body for token refresh
type RefreshTokenRequest struct {
	RefreshToken   string `json:"refresh_token" validate:"required"`
	RecaptchaToken string `json:"recaptcha_token,omitempty"`
}

// ForgotPasswordRequest represents the request body for password reset request
type ForgotPasswordRequest struct {
	Email          string `json:"email" validate:"required,email"`
	RecaptchaToken string `json:"recaptcha_token,omitempty"`
}

// ResetPasswordRequest represents the request body for password reset
type ResetPasswordRequest struct {
	Token          string `json:"token" validate:"required"`
	NewPassword    string `json:"new_password" validate:"required"`
	RecaptchaToken string `json:"recaptcha_token,omitempty"`
}

// UpdateUserRequest represents the request body for user profile update
type UpdateProfileRequest struct {
	FirstName       string `json:"first_name,omitempty"`
	LastName        string `json:"last_name,omitempty"`
	PhoneNumber     string `json:"phone_number,omitempty"`
	Address         string `json:"address,omitempty"`
	ProfileImageURL string `json:"profile_image_url,omitempty"`
	RecaptchaToken  string `json:"recaptcha_token,omitempty"`
}

// change password request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required"`
	RecaptchaToken  string `json:"recaptcha_token,omitempty"`
}

// DeactivateUserRequest represents the request body for account deactivation
type DeactivateUserRequest struct {
	Password       string `json:"password" validate:"required"`
	RecaptchaToken string `json:"recaptcha_token,omitempty"`
}

// VerifyTwoFactorRequest represents the request body for two-factor verification
type VerifyTwoFactorRequest struct {
	Code           string `json:"code" validate:"required"`
	RecaptchaToken string `json:"recaptcha_token,omitempty"`
}

// DisableTwoFactorRequest represents the request body for disabling two-factor authentication
type DisableTwoFactorRequest struct {
	Password       string `json:"password" validate:"required"`
	RecaptchaToken string `json:"recaptcha_token,omitempty"`
}

// VerifyEmailRequest represents the request body for email verification
type VerifyEmailRequest struct {
	Token          string `json:"token" validate:"required"`
	Email          string `json:"email" validate:"required,email"`
	RecaptchaToken string `json:"recaptcha_token,omitempty"`
}

// ResendVerificationEmailRequest represents the request body for resending verification email
type SendVerificationEmailRequest struct {
	Email          string `json:"email" validate:"required,email"`
	RecaptchaToken string `json:"recaptcha_token,omitempty"`
}

// UserResponse represents the user data returned to clients
type UserResponse struct {
	ID        string    `json:"id"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type SendPhoneVerificationRequest struct {
	PhoneNumber    string `json:"phone_number" validate:"required"`
	RecaptchaToken string `json:"recaptcha_token,omitempty"`
}

type VerifyPhoneRequest struct {
	Code           string `json:"code" validate:"required"`
	PhoneNumber    string `json:"phone_number" validate:"required"`
	RecaptchaToken string `json:"recaptcha_token,omitempty"`
}
