// auth/docs/models.go
package docs

// User represents a user in the system
type User struct {
	ID        string `json:"id" example:"123e4567-e89b-12d3-a456-426614174000"`
	Email     string `json:"email" example:"user@example.com"`
	FirstName string `json:"firstName,omitempty" example:"John"`
	LastName  string `json:"lastName,omitempty" example:"Doe"`
	CreatedAt string `json:"createdAt" example:"2023-01-01T00:00:00Z"`
	UpdatedAt string `json:"updatedAt" example:"2023-01-01T00:00:00Z"`
}

// RegisterRequest is used for user registration
type RegisterRequest struct {
	Email     string `json:"email" example:"user@example.com"`
	Password  string `json:"password" example:"StrongP@ssw0rd"`
	FirstName string `json:"firstName,omitempty" example:"John"`
	LastName  string `json:"lastName,omitempty" example:"Doe"`
}

// RegisterResponse is the response for successful registration
type RegisterResponse struct {
	User  User   `json:"user"`
	Token string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// LoginRequest is used for user authentication
type LoginRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"StrongP@ssw0rd"`
}

// LoginResponse is the response for successful authentication
type LoginResponse struct {
	User         User   `json:"user"`
	AccessToken  string `json:"accessToken" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refreshToken" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// LogoutResponse is the response for successful logout
type LogoutResponse struct {
	Message string `json:"message" example:"Successfully logged out"`
}

// RefreshTokenRequest is used to get a new access token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// RefreshTokenResponse is the response for token refresh
type RefreshTokenResponse struct {
	AccessToken  string `json:"accessToken" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refreshToken" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// ForgotPasswordRequest is used to reset password
type ForgotPasswordRequest struct {
	Email string `json:"email" example:"user@example.com"`
}

// ForgotPasswordResponse is the response for password reset request
type ForgotPasswordResponse struct {
	Message string `json:"message" example:"Password reset email sent"`
}

// ResetPasswordRequest is used to set a new password
type ResetPasswordRequest struct {
	Token    string `json:"token" example:"abc123def456"`
	Password string `json:"password" example:"NewStrongP@ssw0rd"`
}

// ResetPasswordResponse is the response for successful password reset
type ResetPasswordResponse struct {
	Message string `json:"message" example:"Password successfully reset"`
}

// UpdateUserRequest is used to update user information
type UpdateUserRequest struct {
	FirstName string `json:"firstName,omitempty" example:"John"`
	LastName  string `json:"lastName,omitempty" example:"Doe"`
	Email     string `json:"email,omitempty" example:"user@example.com"`
}

// UpdateUserResponse is the response for user update
type UpdateUserResponse struct {
	User User `json:"user"`
}

// DeactivateUserResponse is the response for account deactivation
type DeactivateUserResponse struct {
	Message string `json:"message" example:"Account successfully deactivated"`
}

// GetUserResponse is the response for user information retrieval
type GetUserResponse struct {
	User User `json:"user"`
}

// EnableTwoFactorResponse is the response for 2FA enabling
type EnableTwoFactorResponse struct {
	Secret string `json:"secret" example:"JBSWY3DPEHPK3PXP"`
	QrCode string `json:"qrCode" example:"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgA..."`
}

// VerifyTwoFactorRequest is used for 2FA verification
type VerifyTwoFactorRequest struct {
	Code string `json:"code" example:"123456"`
}

// VerifyTwoFactorResponse is the response for 2FA verification
type VerifyTwoFactorResponse struct {
	Valid bool `json:"valid" example:"true"`
}

// DisableTwoFactorResponse is the response for 2FA disabling
type DisableTwoFactorResponse struct {
	Message string `json:"message" example:"Two-factor authentication disabled"`
}

// VerifyEmailRequest is used for email verification
type VerifyEmailRequest struct {
	Token string `json:"token" example:"abc123def456"`
}

// VerifyEmailResponse is the response for email verification
type VerifyEmailResponse struct {
	Valid bool `json:"valid" example:"true"`
}

// ResendVerificationEmailRequest is used to resend the verification email
type ResendVerificationEmailRequest struct {
	Email string `json:"email" example:"user@example.com"`
}

// ResendVerificationEmailResponse is the response for verification email resend
type ResendVerificationEmailResponse struct {
	Message string `json:"message" example:"Verification email sent"`
}

// OAuthCallbackResponse is the response for OAuth callback
type OAuthCallbackResponse struct {
	User         User   `json:"user"`
	AccessToken  string `json:"accessToken" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refreshToken" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error" example:"Invalid credentials"`
	Code    int    `json:"code" example:"401"`
	Message string `json:"message,omitempty" example:"The provided email or password is incorrect"`
}