package types

import "net/http"

// ErrorCode represents a specific error type
type ErrorCode string

// GoAuthError represents a structured API error
type GoAuthError struct {
	Code       ErrorCode `json:"code"`
	Message    string    `json:"message"`
	StatusCode int       `json:"-"`
	Details    any       `json:"details,omitempty"`
}

const (
	// User related errors
	ErrUserNotFound         ErrorCode = "USER_NOT_FOUND"
	ErrUserAlreadyExists    ErrorCode = "USER_ALREADY_EXISTS"
	ErrUserNotActive        ErrorCode = "USER_NOT_ACTIVE"
	ErrUserBlocked          ErrorCode = "USER_BLOCKED"
	ErrEmailNotVerified     ErrorCode = "EMAIL_NOT_VERIFIED"
	ErrPhoneNotVerified     ErrorCode = "PHONE_NOT_VERIFIED"
	ErrAccountDeactivated   ErrorCode = "ACCOUNT_DEACTIVATED"
	ErrEmailAlreadyVerified ErrorCode = "EMAIL_ALREADY_VERIFIED"
	ErrPhoneAlreadyVerified ErrorCode = "PHONE_ALREADY_VERIFIED"
	ErrPhoneAlreadyInUse    ErrorCode = "PHONE_ALREADY_IN_USE"
	// Authentication errors
	ErrInvalidCredentials  ErrorCode = "INVALID_CREDENTIALS"
	ErrInvalidToken        ErrorCode = "INVALID_TOKEN"
	ErrTokenExpired        ErrorCode = "TOKEN_EXPIRED"
	ErrTokenNotFound       ErrorCode = "TOKEN_NOT_FOUND"
	ErrTokenAlreadyUsed    ErrorCode = "TOKEN_ALREADY_USED"
	ErrInvalidRefreshToken ErrorCode = "INVALID_REFRESH_TOKEN"
	ErrAccountLocked       ErrorCode = "ACCOUNT_LOCKED"
	ErrPasswordExpired     ErrorCode = "PASSWORD_EXPIRED"
	// session errors
	ErrInvalidSession  ErrorCode = "INVALID_SESSION"
	ErrSessionNotFound ErrorCode = "SESSION_NOT_FOUND"
	ErrSessionExpired  ErrorCode = "SESSION_EXPIRED"
	ErrSessionInvalid  ErrorCode = "SESSION_INVALID"

	// invalid request ip
	ErrInvalidRequestIP ErrorCode = "INVALID_REQUEST_IP"

	// Validation errors
	ErrInvalidEmail       ErrorCode = "INVALID_EMAIL"
	ErrInvalidPassword    ErrorCode = "INVALID_PASSWORD"
	ErrInvalidPhone       ErrorCode = "INVALID_PHONE"
	ErrMissingFields      ErrorCode = "MISSING_FIELDS"
	ErrInvalidRequestBody ErrorCode = "INVALID_REQUEST_BODY"
	ErrInvalidJSON        ErrorCode = "INVALID_JSON"
	ErrValidation         ErrorCode = "VALIDATION_ERROR"

	// Authorization errors
	ErrUnauthorized ErrorCode = "UNAUTHORIZED"
	ErrForbidden    ErrorCode = "FORBIDDEN"
	ErrInvalidCSRF  ErrorCode = "INVALID_CSRF"

	// Two-factor errors
	ErrTwoFactorAlreadyEnabled ErrorCode = "TWO_FACTOR_ALREADY_ENABLED"
	ErrTwoFactorNotEnabled     ErrorCode = "TWO_FACTOR_NOT_ENABLED"
	ErrTwoFactorNotFound       ErrorCode = "TWO_FACTOR_NOT_FOUND"
	ErrTwoFactorInvalid        ErrorCode = "TWO_FACTOR_INVALID"
	ErrTwoFactorExpired        ErrorCode = "TWO_FACTOR_EXPIRED"
	ErrTwoFactorAlreadyUsed    ErrorCode = "TWO_FACTOR_ALREADY_USED"

	// Rate limiting
	ErrRateLimitExceeded ErrorCode = "RATE_LIMIT_EXCEEDED"
	ErrTooManyRequests   ErrorCode = "TOO_MANY_REQUESTS"

	// Method errors
	ErrMethodNotAllowed ErrorCode = "METHOD_NOT_ALLOWED"

	// System errors
	ErrInternalError      ErrorCode = "INTERNAL_ERROR"
	ErrDatabaseError      ErrorCode = "DATABASE_ERROR"
	ErrEmailSendFailed    ErrorCode = "EMAIL_SEND_FAILED"
	ErrSmsSendFailed      ErrorCode = "SMS_SEND_FAILED"
	ErrConfigurationError ErrorCode = "CONFIGURATION_ERROR"

	// Verification errors
	ErrInvalidVerificationToken ErrorCode = "INVALID_VERIFICATION_TOKEN"
	ErrVerificationTokenExpired ErrorCode = "VERIFICATION_TOKEN_EXPIRED"
	ErrInvalidVerificationCode  ErrorCode = "INVALID_VERIFICATION_CODE"
	ErrVerificationCodeExpired  ErrorCode = "VERIFICATION_CODE_EXPIRED"

	// unknown error
	ErrUnknown ErrorCode = "UNKNOWN_ERROR"

	// custom errors
	ErrCustom ErrorCode = "CUSTOM_ERROR"
)

// Error implements the error interface
func (e *GoAuthError) Error() string {
	return e.Message
}

// NewGoAuthError creates a new API error
func NewGoAuthError(code ErrorCode, message string, statusCode int) *GoAuthError {
	return &GoAuthError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
	}
}

// User related error factory functions
func NewUserNotFoundError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrUserNotFound,
		Message:    "User not found",
		StatusCode: http.StatusNotFound,
	}
}

func NewUserAlreadyExistsError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrUserAlreadyExists,
		Message:    "User with this email already exists",
		StatusCode: http.StatusConflict,
	}
}

func NewUserNotActiveError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrUserNotActive,
		Message:    "User account is not active",
		StatusCode: http.StatusForbidden,
	}
}

func NewUserBlockedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrUserBlocked,
		Message:    "User account is blocked",
		StatusCode: http.StatusForbidden,
	}
}

func NewEmailNotVerifiedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrEmailNotVerified,
		Message:    "Email address not verified",
		StatusCode: http.StatusForbidden,
	}
}

func NewPhoneNotVerifiedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrPhoneNotVerified,
		Message:    "Phone number not verified",
		StatusCode: http.StatusForbidden,
	}
}

func NewAccountDeactivatedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrAccountDeactivated,
		Message:    "Account has been deactivated",
		StatusCode: http.StatusForbidden,
	}
}

func NewEmailAlreadyVerifiedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrEmailAlreadyVerified,
		Message:    "Email address already verified",
		StatusCode: http.StatusBadRequest,
	}
}

func NewPhoneAlreadyVerifiedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrPhoneAlreadyVerified,
		Message:    "Phone number already verified",
		StatusCode: http.StatusBadRequest,
	}
}

func NewPhoneAlreadyInUseError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrPhoneAlreadyInUse,
		Message:    "Phone number already in use",
		StatusCode: http.StatusBadRequest,
	}
}

// Authentication error factory functions
func NewInvalidCredentialsError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidCredentials,
		Message:    "Invalid email or password",
		StatusCode: http.StatusUnauthorized,
	}
}

func NewInvalidTokenError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidToken,
		Message:    "Invalid or expired token",
		StatusCode: http.StatusUnauthorized,
	}
}

func NewTokenExpiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTokenExpired,
		Message:    "Token has expired",
		StatusCode: http.StatusUnauthorized,
	}
}

func NewTokenNotFoundError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTokenNotFound,
		Message:    "Token not found",
		StatusCode: http.StatusBadRequest,
	}
}

func NewTokenAlreadyUsedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTokenAlreadyUsed,
		Message:    "Token already used",
		StatusCode: http.StatusBadRequest,
	}
}

func NewInvalidRefreshTokenError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidRefreshToken,
		Message:    "Invalid refresh token",
		StatusCode: http.StatusUnauthorized,
	}
}

func NewAccountLockedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrAccountLocked,
		Message:    "Account is temporarily locked due to too many failed attempts",
		StatusCode: http.StatusLocked,
	}
}

func NewPasswordExpiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrPasswordExpired,
		Message:    "Password has expired",
		StatusCode: http.StatusUnauthorized,
	}
}

// Validation error factory functions
func NewInvalidEmailError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidEmail,
		Message:    "Invalid email format",
		StatusCode: http.StatusBadRequest,
	}
}

func NewInvalidPasswordError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidPassword,
		Message:    "Invalid password format",
		StatusCode: http.StatusBadRequest,
	}
}

func NewInvalidPhoneError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidPhone,
		Message:    "Invalid phone number format",
		StatusCode: http.StatusBadRequest,
	}
}

func NewMissingFieldsError(fields string) *GoAuthError {
	message := "Missing required fields"
	if fields != "" {
		message = "Missing required fields: " + fields
	}
	return &GoAuthError{
		Code:       ErrMissingFields,
		Message:    message,
		StatusCode: http.StatusBadRequest,
	}
}

func NewValidationError(message string) *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidRequestBody,
		Message:    message,
		StatusCode: http.StatusBadRequest,
	}
}

func NewInvalidJSONError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidJSON,
		Message:    "Invalid JSON format",
		StatusCode: http.StatusBadRequest,
	}
}

// Authorization error factory functions
func NewUnauthorizedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrUnauthorized,
		Message:    "Unauthorized access",
		StatusCode: http.StatusUnauthorized,
	}
}

func NewForbiddenError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrForbidden,
		Message:    "Access forbidden",
		StatusCode: http.StatusForbidden,
	}
}

func NewInvalidCSRFError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidCSRF,
		Message:    "Invalid CSRF token",
		StatusCode: http.StatusForbidden,
	}
}

// Rate limiting error factory functions
func NewRateLimitExceededError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrRateLimitExceeded,
		Message:    "Rate limit exceeded",
		StatusCode: http.StatusTooManyRequests,
	}
}

func NewTooManyRequestsError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTooManyRequests,
		Message:    "Too many requests",
		StatusCode: http.StatusTooManyRequests,
	}
}

// Method error factory functions
func NewMethodNotAllowedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrMethodNotAllowed,
		Message:    "Method not allowed",
		StatusCode: http.StatusMethodNotAllowed,
	}
}

// System error factory functions
func NewInternalError(message string) *GoAuthError {
	if message == "" {
		message = "An unexpected error occurred"
	}
	return &GoAuthError{
		Code:       ErrInternalError,
		Message:    message,
		StatusCode: http.StatusInternalServerError,
	}
}

func NewDatabaseError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrDatabaseError,
		Message:    "Database operation failed",
		StatusCode: http.StatusInternalServerError,
	}
}

func NewEmailSendFailedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrEmailSendFailed,
		Message:    "Failed to send email",
		StatusCode: http.StatusInternalServerError,
	}
}

func NewSmsSendFailedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrSmsSendFailed,
		Message:    "Failed to send SMS",
		StatusCode: http.StatusInternalServerError,
	}
}

func NewConfigurationError(message *string) *GoAuthError {
	if message == nil {
		msg := "Configuration error"
		message = &msg
	}
	return &GoAuthError{
		Code:       ErrConfigurationError,
		Message:    "Configuration error",
		StatusCode: http.StatusInternalServerError,
	}
}

func NewUnknownError(message *string) *GoAuthError {
	if message == nil {
		msg := "An unexpected error occurred"
		message = &msg
	}
	return &GoAuthError{
		Code:       ErrUnknown,
		Message:    *message,
		StatusCode: http.StatusInternalServerError,
	}
}

func NewInvalidSessionError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidSession,
		Message:    "Invalid session",
		StatusCode: http.StatusUnauthorized,
	}
}

func NewSessionNotFoundError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrSessionNotFound,
		Message:    "Session not found",
		StatusCode: http.StatusNotFound,
	}
}

func NewSessionExpiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrSessionExpired,
		Message:    "Session has expired",
		StatusCode: http.StatusUnauthorized,
	}
}

func NewSessionInvalidError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrSessionInvalid,
		Message:    "Session is invalid",
		StatusCode: http.StatusUnauthorized,
	}
}

func NewCustomError(message string) *GoAuthError {
	return &GoAuthError{
		Code:    ErrCustom,
		Message: message,
	}
}

func NewTwoFactorAlreadyEnabledError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTwoFactorAlreadyEnabled,
		Message:    "Two-factor authentication is already enabled",
		StatusCode: http.StatusBadRequest,
	}
}

func NewTwoFactorNotEnabledError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTwoFactorNotEnabled,
		Message:    "Two-factor authentication is not enabled",
		StatusCode: http.StatusBadRequest,
	}
}

func NewTwoFactorInvalidError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTwoFactorInvalid,
		Message:    "Two-factor authentication is invalid",
		StatusCode: http.StatusBadRequest,
	}
}

func NewTwoFactorExpiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTwoFactorExpired,
		Message:    "Two-factor authentication has expired",
		StatusCode: http.StatusBadRequest,
	}
}

func NewTwoFactorNotFoundError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTwoFactorNotFound,
		Message:    "Two-factor authentication not found",
		StatusCode: http.StatusBadRequest,
	}
}

func NewTwoFactorAlreadyUsedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTwoFactorAlreadyUsed,
		Message:    "Two-factor authentication has already been used",
		StatusCode: http.StatusBadRequest,
	}
}

func NewInvalidVerificationTokenError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidVerificationToken,
		Message:    "Invalid verification token",
		StatusCode: http.StatusBadRequest,
	}
}

func NewVerificationTokenExpiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrVerificationTokenExpired,
		Message:    "Verification token has expired",
		StatusCode: http.StatusBadRequest,
	}
}

func NewInvalidVerificationCodeError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidVerificationCode,
		Message:    "Invalid verification code",
		StatusCode: http.StatusBadRequest,
	}
}

func NewVerificationCodeExpiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrVerificationCodeExpired,
		Message:    "Verification code has expired",
		StatusCode: http.StatusBadRequest,
	}
}
