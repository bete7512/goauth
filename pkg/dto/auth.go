package dto

import "time"

// RegisterRequest represents user registration request
type RegisterRequest struct {
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,min=8"`
	FirstName   string `json:"first_name" validate:"required"`
	LastName    string `json:"last_name" validate:"required"`
	PhoneNumber string `json:"phone_number" `
}

// RegisterResponse represents user registration response
type RegisterResponse struct {
	Message string     `json:"message"`
	Status  int        `json:"status"`
	User    UserData   `json:"user"`
	Tokens  *TokenData `json:"tokens,omitempty"`
}

type SendPhoneVerificationRequest struct {
	PhoneNumber string `json:"phone_number" validate:"required"`
}

// LoginRequest represents user login request
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginResponse represents user login response
type LoginResponse struct {
	SessionId string    `json:"session_id"`
	Status    int       `json:"status"`
	Message   string    `json:"message"`
	User      UserData  `json:"user"`
	Tokens    TokenData `json:"tokens"`
}

// RefreshTokenResponse represents token refresh response
type RefreshTokenResponse struct {
	SessionId string    `json:"session_id"`
	Status    int       `json:"status"`
	Message   string    `json:"message"`
	Tokens    TokenData `json:"tokens"`
}

// ForgotPasswordRequest represents forgot password request
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordRequest represents password reset request
type ResetPasswordRequest struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
}

// MagicLinkRequest represents magic link request
type MagicLinkRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// MagicLinkVerificationRequest represents magic link verification request
type MagicLinkVerificationRequest struct {
	Token     string `json:"token" validate:"required"`
	Email     string `json:"email" validate:"required,email"`
	Ip        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	DeviceId  string `json:"device_id"`
	Location  string `json:"location"`
}

// RegisterWithInvitationRequest represents invitation-based registration request
type RegisterWithInvitationRequest struct {
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,min=8"`
	FirstName       string `json:"first_name" validate:"required"`
	LastName        string `json:"last_name" validate:"required"`
	InvitationToken string `json:"invitation_token" validate:"required"`
}

// TokenData represents authentication tokens
type TokenData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// UserData represents user information in responses
type UserData struct {
	ID               string     `json:"id"`
	Email            string     `json:"email"`
	FirstName        string     `json:"first_name"`
	LastName         string     `json:"last_name"`
	EmailVerified    *bool      `json:"email_verified"`
	PhoneVerified    *bool      `json:"phone_verified"`
	TwoFactorEnabled *bool      `json:"two_factor_enabled"`
	Active           *bool      `json:"active"`
	IsAdmin          *bool      `json:"is_admin"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
}
