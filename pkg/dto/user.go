package dto

// UpdateProfileRequest represents profile update request
type UpdateProfileRequest struct {
	FirstName   string `json:"first_name,omitempty"`
	LastName    string `json:"last_name,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
}

// UserResponse represents user information response
type UserResponse struct {
	Message string   `json:"message"`
	User    UserData `json:"user"`
}

// DeactivateUserRequest represents user deactivation request
type DeactivateUserRequest struct {
	Password string `json:"password" validate:"required"`
}

type SendEmailVerificationRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// EmailVerificationRequest represents email verification request
type EmailVerificationRequest struct {
	Token string `json:"token" validate:"required"`
	Email string `json:"email" validate:"required,email"`
}

// PhoneVerificationRequest represents phone verification request
type PhoneVerificationRequest struct {
	Code        string `json:"code" validate:"required"`
	PhoneNumber string `json:"phone_number" validate:"required"`
}

// ActionConfirmationRequest represents action confirmation request
type ActionConfirmationRequest struct {
	ActionType string                 `json:"action_type" validate:"required"`
	Data       map[string]interface{} `json:"data,omitempty"`
}

// ActionConfirmationVerificationRequest represents action confirmation verification request
type ActionConfirmationVerificationRequest struct {
	Code string `json:"code" validate:"required"`
}

// TwoFactorSetupResponse represents two-factor setup response
type TwoFactorSetupResponse struct {
	Message     string   `json:"message"`
	Method      string   `json:"method"`
	QRCode      string   `json:"qr_code,omitempty"`
	Secret      string   `json:"secret,omitempty"`
	BackupCodes []string `json:"backup_codes,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
}

// EnableTwoFactorRequest represents two-factor enable request
type EnableTwoFactorRequest struct {
	Method string `json:"method" validate:"required,oneof=email sms totp"`
}

// TwoFactorVerificationRequest represents two-factor verification request
type TwoFactorVerificationRequest struct {
	Code   string `json:"code" validate:"required"`
	Method string `json:"method,omitempty" validate:"omitempty,oneof=email sms totp backup"`
}

// DisableTwoFactorRequest represents two-factor disable request
type DisableTwoFactorRequest struct {
	Password string `json:"password" validate:"required"`
}

// TwoFactorStatusResponse represents two-factor status response
type TwoFactorStatusResponse struct {
	Enabled bool     `json:"enabled"`
	Methods []string `json:"methods,omitempty"`
}

// ResendTwoFactorCodeRequest represents resend two-factor code request
type ResendTwoFactorCodeRequest struct {
	Method string `json:"method" validate:"required,oneof=email sms"`
}

// VerifyTwoFactorSetupRequest represents two-factor setup verification request
type VerifyTwoFactorSetupRequest struct {
	Code string `json:"code" validate:"required"`
}

// TwoFactorLoginRequest represents two-factor login request
type TwoFactorLoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
	Code     string `json:"code" validate:"required"`
	Method   string `json:"method,omitempty" validate:"omitempty,oneof=email sms totp backup"`
}
