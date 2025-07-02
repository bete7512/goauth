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

// EmailVerificationRequest represents email verification request
type EmailVerificationRequest struct {
	Token string `json:"token" validate:"required"`
}

// PhoneVerificationRequest represents phone verification request
type PhoneVerificationRequest struct {
	Code string `json:"code" validate:"required"`
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
	QRCode      string   `json:"qr_code,omitempty"`
	Secret      string   `json:"secret,omitempty"`
	BackupCodes []string `json:"backup_codes,omitempty"`
}

// EnableTwoFactorRequest represents two-factor enable request
type EnableTwoFactorRequest struct {
	Method string `json:"method" validate:"required"`
}

// TwoFactorVerificationRequest represents two-factor verification request
type TwoFactorVerificationRequest struct {
	Code string `json:"code" validate:"required"`
}

// DisableTwoFactorRequest represents two-factor disable request
type DisableTwoFactorRequest struct {
	Password string `json:"password" validate:"required"`
}
