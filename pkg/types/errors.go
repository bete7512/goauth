package types

import (
	"fmt"
	"net/http"
	"time"
)

// ErrorCode represents a specific error type
type ErrorCode string

// GoAuthError represents a structured API error
type GoAuthError struct {
	Code       ErrorCode `json:"code"`
	Message    string    `json:"message"`
	StatusCode int       `json:"-"`
	Details    any       `json:"details,omitempty"`
	Err        error     `json:"-"`
}

// Error codes. A GoAuthError carries one in Code, and API error responses
// return it in the "code" field. Each code has a New...Error constructor.
const (
	// User related errors
	ErrUserNotFound          ErrorCode = "USER_NOT_FOUND"
	ErrUserAlreadyExists     ErrorCode = "USER_ALREADY_EXISTS"
	ErrUserNotActive         ErrorCode = "USER_NOT_ACTIVE"
	ErrUserBlocked           ErrorCode = "USER_BLOCKED"
	ErrEmailNotVerified      ErrorCode = "EMAIL_NOT_VERIFIED"
	ErrPhoneNotVerified      ErrorCode = "PHONE_NOT_VERIFIED"
	ErrAccountDeactivated    ErrorCode = "ACCOUNT_DEACTIVATED"
	ErrEmailAlreadyVerified  ErrorCode = "EMAIL_ALREADY_VERIFIED"
	ErrPhoneAlreadyVerified  ErrorCode = "PHONE_ALREADY_VERIFIED"
	ErrPhoneAlreadyInUse     ErrorCode = "PHONE_ALREADY_IN_USE"
	ErrUsernameAlreadyExists ErrorCode = "USERNAME_ALREADY_EXISTS"
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
	ErrUnauthorized    ErrorCode = "UNAUTHORIZED"
	ErrForbidden       ErrorCode = "FORBIDDEN"
	ErrInvalidCSRF     ErrorCode = "INVALID_CSRF"
	ErrCaptchaRequired ErrorCode = "CAPTCHA_REQUIRED"
	ErrCaptchaFailed   ErrorCode = "CAPTCHA_FAILED"

	// Passkey errors
	ErrPasskeyNotFound ErrorCode = "PASSKEY_NOT_FOUND"
	ErrPasskeyInvalid  ErrorCode = "PASSKEY_INVALID"

	// Two-factor errors
	ErrTwoFactorRequired       ErrorCode = "TWO_FACTOR_REQUIRED"
	ErrTwoFactorAlreadyEnabled ErrorCode = "TWO_FACTOR_ALREADY_ENABLED"
	ErrTwoFactorNotEnabled     ErrorCode = "TWO_FACTOR_NOT_ENABLED"
	ErrTwoFactorNotFound       ErrorCode = "TWO_FACTOR_NOT_FOUND"
	ErrTwoFactorInvalid        ErrorCode = "TWO_FACTOR_INVALID"
	ErrTwoFactorExpired        ErrorCode = "TWO_FACTOR_EXPIRED"
	ErrTwoFactorAlreadyUsed    ErrorCode = "TWO_FACTOR_ALREADY_USED"

	// Method errors
	ErrMethodNotAllowed ErrorCode = "METHOD_NOT_ALLOWED"

	// System errors
	ErrInternalError      ErrorCode = "INTERNAL_ERROR"
	ErrRateLimitExceeded  ErrorCode = "RATE_LIMIT_EXCEEDED"
	ErrDatabaseError      ErrorCode = "DATABASE_ERROR"
	ErrEmailSendFailed    ErrorCode = "EMAIL_SEND_FAILED"
	ErrSmsSendFailed      ErrorCode = "SMS_SEND_FAILED"
	ErrConfigurationError ErrorCode = "CONFIGURATION_ERROR"

	// Verification errors
	ErrInvalidVerificationToken ErrorCode = "INVALID_VERIFICATION_TOKEN"
	ErrVerificationTokenExpired ErrorCode = "VERIFICATION_TOKEN_EXPIRED"
	ErrInvalidVerificationCode  ErrorCode = "INVALID_VERIFICATION_CODE"
	ErrVerificationCodeExpired  ErrorCode = "VERIFICATION_CODE_EXPIRED"

	// OAuth errors
	ErrOAuthProviderNotFound       ErrorCode = "OAUTH_PROVIDER_NOT_FOUND"
	ErrOAuthProviderDisabled       ErrorCode = "OAUTH_PROVIDER_DISABLED"
	ErrOAuthInvalidState           ErrorCode = "OAUTH_INVALID_STATE"
	ErrOAuthStateExpired           ErrorCode = "OAUTH_STATE_EXPIRED"
	ErrOAuthStateUsed              ErrorCode = "OAUTH_STATE_USED"
	ErrOAuthTokenExchange          ErrorCode = "OAUTH_TOKEN_EXCHANGE_FAILED"
	ErrOAuthUserInfo               ErrorCode = "OAUTH_USER_INFO_FAILED"
	ErrOAuthEmailExists            ErrorCode = "OAUTH_EMAIL_EXISTS"
	ErrOAuthSignupDisabled         ErrorCode = "OAUTH_SIGNUP_DISABLED"
	ErrOAuthProviderError          ErrorCode = "OAUTH_PROVIDER_ERROR"
	ErrOAuthNotLinked              ErrorCode = "OAUTH_NOT_LINKED"
	ErrOAuthAlreadyLinked          ErrorCode = "OAUTH_ALREADY_LINKED"
	ErrOAuthEmailRequired          ErrorCode = "OAUTH_EMAIL_REQUIRED"
	ErrOAuthEmailUnverified        ErrorCode = "OAUTH_EMAIL_UNVERIFIED"
	ErrOAuthAccountLinkingDisabled ErrorCode = "OAUTH_ACCOUNT_LINKING_DISABLED"

	// Organization errors
	ErrOrgNotFound             ErrorCode = "ORG_NOT_FOUND"
	ErrOrgSlugTaken            ErrorCode = "ORG_SLUG_TAKEN"
	ErrOrgMemberExists         ErrorCode = "ORG_MEMBER_EXISTS"
	ErrOrgMemberNotFound       ErrorCode = "ORG_MEMBER_NOT_FOUND"
	ErrOrgNotMember            ErrorCode = "ORG_NOT_MEMBER"
	ErrOrgInsufficientRole     ErrorCode = "ORG_INSUFFICIENT_ROLE"
	ErrOrgCannotRemoveOwner    ErrorCode = "ORG_CANNOT_REMOVE_OWNER"
	ErrOrgMaxMembers           ErrorCode = "ORG_MAX_MEMBERS"
	ErrInvitationNotFound      ErrorCode = "INVITATION_NOT_FOUND"
	ErrInvitationExpired       ErrorCode = "INVITATION_EXPIRED"
	ErrInvitationExists        ErrorCode = "INVITATION_ALREADY_EXISTS"
	ErrInvitationEmailMismatch ErrorCode = "INVITATION_EMAIL_MISMATCH"

	// unknown error
	ErrUnknown ErrorCode = "UNKNOWN_ERROR"

	// custom errors
	ErrCustom ErrorCode = "CUSTOM_ERROR"
)

// Error implements the error interface
func (e *GoAuthError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s", e.Message, e.Err.Error())
	}
	return e.Message
}

// Unwrap returns the underlying error for errors.Is/As support
func (e *GoAuthError) Unwrap() error {
	return e.Err
}

// Wrap sets the underlying error and returns the GoAuthError for chaining
func (e *GoAuthError) Wrap(err error) *GoAuthError {
	e.Err = err
	return e
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

// NewUserNotFoundError returns the USER_NOT_FOUND error (HTTP 404) with the message "User not found".
func NewUserNotFoundError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrUserNotFound,
		Message:    "User not found",
		StatusCode: http.StatusNotFound,
	}
}

// NewUserAlreadyExistsError returns the USER_ALREADY_EXISTS error (HTTP 409) with the message "User with this email already exists".
func NewUserAlreadyExistsError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrUserAlreadyExists,
		Message:    "User with this email already exists",
		StatusCode: http.StatusConflict,
	}
}

// NewUserNotActiveError returns the USER_NOT_ACTIVE error (HTTP 403) with the message "User account is not active".
func NewUserNotActiveError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrUserNotActive,
		Message:    "User account is not active",
		StatusCode: http.StatusForbidden,
	}
}

// NewUserBlockedError returns the USER_BLOCKED error (HTTP 403) with the message "User account is blocked".
func NewUserBlockedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrUserBlocked,
		Message:    "User account is blocked",
		StatusCode: http.StatusForbidden,
	}
}

// NewEmailNotVerifiedError returns the EMAIL_NOT_VERIFIED error (HTTP 403) with the message "Email address not verified".
func NewEmailNotVerifiedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrEmailNotVerified,
		Message:    "Email address not verified",
		StatusCode: http.StatusForbidden,
	}
}

// NewPhoneNotVerifiedError returns the PHONE_NOT_VERIFIED error (HTTP 403) with the message "Phone number not verified".
func NewPhoneNotVerifiedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrPhoneNotVerified,
		Message:    "Phone number not verified",
		StatusCode: http.StatusForbidden,
	}
}

// NewAccountDeactivatedError returns the ACCOUNT_DEACTIVATED error (HTTP 403) with the message "Account has been deactivated".
func NewAccountDeactivatedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrAccountDeactivated,
		Message:    "Account has been deactivated",
		StatusCode: http.StatusForbidden,
	}
}

// NewEmailAlreadyVerifiedError returns the EMAIL_ALREADY_VERIFIED error (HTTP 400) with the message "Email address already verified".
func NewEmailAlreadyVerifiedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrEmailAlreadyVerified,
		Message:    "Email address already verified",
		StatusCode: http.StatusBadRequest,
	}
}

// NewPhoneAlreadyVerifiedError returns the PHONE_ALREADY_VERIFIED error (HTTP 400) with the message "Phone number already verified".
func NewPhoneAlreadyVerifiedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrPhoneAlreadyVerified,
		Message:    "Phone number already verified",
		StatusCode: http.StatusBadRequest,
	}
}

// NewPhoneAlreadyInUseError returns the PHONE_ALREADY_IN_USE error (HTTP 400) with the message "Phone number already in use".
func NewPhoneAlreadyInUseError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrPhoneAlreadyInUse,
		Message:    "Phone number already in use",
		StatusCode: http.StatusBadRequest,
	}
}

// Authentication error factory functions

// NewInvalidCredentialsError returns the INVALID_CREDENTIALS error (HTTP 401) with the message "Invalid email or password".
func NewInvalidCredentialsError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidCredentials,
		Message:    "Invalid email or password",
		StatusCode: http.StatusUnauthorized,
	}
}

// NewInvalidTokenError returns the INVALID_TOKEN error (HTTP 401) with the message "Invalid or expired token".
func NewInvalidTokenError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidToken,
		Message:    "Invalid or expired token",
		StatusCode: http.StatusUnauthorized,
	}
}

// NewTokenExpiredError returns the TOKEN_EXPIRED error (HTTP 401) with the message "Token has expired".
func NewTokenExpiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTokenExpired,
		Message:    "Token has expired",
		StatusCode: http.StatusUnauthorized,
	}
}

// NewTokenNotFoundError returns the TOKEN_NOT_FOUND error (HTTP 400) with the message "Token not found".
func NewTokenNotFoundError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTokenNotFound,
		Message:    "Token not found",
		StatusCode: http.StatusBadRequest,
	}
}

// NewTokenAlreadyUsedError returns the TOKEN_ALREADY_USED error (HTTP 400) with the message "Token already used".
func NewTokenAlreadyUsedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTokenAlreadyUsed,
		Message:    "Token already used",
		StatusCode: http.StatusBadRequest,
	}
}

// NewInvalidRefreshTokenError returns the INVALID_REFRESH_TOKEN error (HTTP 401) with the message "Invalid refresh token".
func NewInvalidRefreshTokenError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidRefreshToken,
		Message:    "Invalid refresh token",
		StatusCode: http.StatusUnauthorized,
	}
}

// NewAccountLockedError returns the ACCOUNT_LOCKED error (HTTP 423) with the message "Account is temporarily locked due to too many failed attempts".
func NewAccountLockedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrAccountLocked,
		Message:    "Account is temporarily locked due to too many failed attempts",
		StatusCode: http.StatusLocked,
	}
}

// NewPasswordExpiredError returns the PASSWORD_EXPIRED error (HTTP 401) with the message "Password has expired".
func NewPasswordExpiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrPasswordExpired,
		Message:    "Password has expired",
		StatusCode: http.StatusUnauthorized,
	}
}

// Validation error factory functions

// NewInvalidEmailError returns the INVALID_EMAIL error (HTTP 400) with the message "Invalid email format".
func NewInvalidEmailError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidEmail,
		Message:    "Invalid email format",
		StatusCode: http.StatusBadRequest,
	}
}

// NewInvalidPasswordError returns the INVALID_PASSWORD error (HTTP 400) with the message "Invalid password format".
func NewInvalidPasswordError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidPassword,
		Message:    "Invalid password format",
		StatusCode: http.StatusBadRequest,
	}
}

// NewInvalidPhoneError returns the INVALID_PHONE error (HTTP 400) with the message "Invalid phone number format".
func NewInvalidPhoneError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidPhone,
		Message:    "Invalid phone number format",
		StatusCode: http.StatusBadRequest,
	}
}

// NewMissingFieldsError returns the MISSING_FIELDS error (HTTP 400) with the message "Missing required fields", followed by fields when it is not empty.
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

// NewValidationError returns the INVALID_REQUEST_BODY error (HTTP 400) with the given message.
func NewValidationError(message string) *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidRequestBody,
		Message:    message,
		StatusCode: http.StatusBadRequest,
	}
}

// NewInvalidJSONError returns the INVALID_JSON error (HTTP 400) with the message "Invalid JSON format".
func NewInvalidJSONError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidJSON,
		Message:    "Invalid JSON format",
		StatusCode: http.StatusBadRequest,
	}
}

// Authorization error factory functions

// NewUnauthorizedError returns the UNAUTHORIZED error (HTTP 401) with the message "Unauthorized access".
func NewUnauthorizedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrUnauthorized,
		Message:    "Unauthorized access",
		StatusCode: http.StatusUnauthorized,
	}
}

// NewForbiddenError returns the FORBIDDEN error (HTTP 403) with the message "Access forbidden".
func NewForbiddenError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrForbidden,
		Message:    "Access forbidden",
		StatusCode: http.StatusForbidden,
	}
}

// NewInvalidCSRFError returns the INVALID_CSRF error (HTTP 403) with the message "Invalid CSRF token".
func NewInvalidCSRFError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidCSRF,
		Message:    "Invalid CSRF token",
		StatusCode: http.StatusForbidden,
	}
}

// NewCaptchaRequiredError returns the CAPTCHA_REQUIRED error (HTTP 403) with the message "Captcha token required".
func NewCaptchaRequiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrCaptchaRequired,
		Message:    "Captcha token required",
		StatusCode: http.StatusForbidden,
	}
}

// NewCaptchaFailedError returns the CAPTCHA_FAILED error (HTTP 403) with the message "Captcha verification failed".
func NewCaptchaFailedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrCaptchaFailed,
		Message:    "Captcha verification failed",
		StatusCode: http.StatusForbidden,
	}
}

// Method error factory functions

// NewMethodNotAllowedError returns the METHOD_NOT_ALLOWED error (HTTP 405) with the message "Method not allowed".
func NewMethodNotAllowedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrMethodNotAllowed,
		Message:    "Method not allowed",
		StatusCode: http.StatusMethodNotAllowed,
	}
}

// System error factory functions

// NewInternalError returns the INTERNAL_ERROR error (HTTP 500) with the given message, or "An unexpected error occurred" when it is empty.
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

// NewUsernameAlreadyExistsError returns the USERNAME_ALREADY_EXISTS error (HTTP 400) with the message "Username already exists".
func NewUsernameAlreadyExistsError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrUsernameAlreadyExists,
		Message:    "Username already exists",
		StatusCode: http.StatusBadRequest,
	}
}

// NewDatabaseError returns the DATABASE_ERROR error (HTTP 500) with the message "Database operation failed".
func NewDatabaseError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrDatabaseError,
		Message:    "Database operation failed",
		StatusCode: http.StatusInternalServerError,
	}
}

// NewEmailSendFailedError returns the EMAIL_SEND_FAILED error (HTTP 500) with the message "Failed to send email".
func NewEmailSendFailedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrEmailSendFailed,
		Message:    "Failed to send email",
		StatusCode: http.StatusInternalServerError,
	}
}

// NewSmsSendFailedError returns the SMS_SEND_FAILED error (HTTP 500) with the message "Failed to send SMS".
func NewSmsSendFailedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrSmsSendFailed,
		Message:    "Failed to send SMS",
		StatusCode: http.StatusInternalServerError,
	}
}

// NewConfigurationError returns the CONFIGURATION_ERROR error (HTTP 500) with the given message, or "Configuration error" when it is nil.
func NewConfigurationError(message *string) *GoAuthError {
	if message == nil {
		msg := "Configuration error"
		message = &msg
	}
	return &GoAuthError{
		Code:       ErrConfigurationError,
		Message:    *message,
		StatusCode: http.StatusInternalServerError,
	}
}

// NewUnknownError returns the UNKNOWN_ERROR error (HTTP 500) with the given message, or "An unexpected error occurred" when it is nil.
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

// NewInvalidSessionError returns the INVALID_SESSION error (HTTP 401) with the message "Invalid session".
func NewInvalidSessionError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidSession,
		Message:    "Invalid session",
		StatusCode: http.StatusUnauthorized,
	}
}

// NewSessionNotFoundError returns the SESSION_NOT_FOUND error (HTTP 404) with the message "Session not found".
func NewSessionNotFoundError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrSessionNotFound,
		Message:    "Session not found",
		StatusCode: http.StatusNotFound,
	}
}

// NewSessionExpiredError returns the SESSION_EXPIRED error (HTTP 401) with the message "Session has expired".
func NewSessionExpiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrSessionExpired,
		Message:    "Session has expired",
		StatusCode: http.StatusUnauthorized,
	}
}

// NewSessionInvalidError returns the SESSION_INVALID error (HTTP 401) with the message "Session is invalid".
func NewSessionInvalidError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrSessionInvalid,
		Message:    "Session is invalid",
		StatusCode: http.StatusUnauthorized,
	}
}

// NewCustomError returns the CUSTOM_ERROR error with the given message and no HTTP status set.
func NewCustomError(message string) *GoAuthError {
	return &GoAuthError{
		Code:    ErrCustom,
		Message: message,
	}
}

// NewTwoFactorRequiredError returns the TWO_FACTOR_REQUIRED error (HTTP 200) with the message "Two-factor authentication required" and the given details.
func NewTwoFactorRequiredError(details map[string]any) *GoAuthError {
	return &GoAuthError{
		Code:       ErrTwoFactorRequired,
		Message:    "Two-factor authentication required",
		StatusCode: http.StatusOK, // 200 OK, not an error - it's a challenge
		Details:    details,
	}
}

// NewTwoFactorAlreadyEnabledError returns the TWO_FACTOR_ALREADY_ENABLED error (HTTP 400) with the message "Two-factor authentication is already enabled".
func NewTwoFactorAlreadyEnabledError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTwoFactorAlreadyEnabled,
		Message:    "Two-factor authentication is already enabled",
		StatusCode: http.StatusBadRequest,
	}
}

// NewTwoFactorNotEnabledError returns the TWO_FACTOR_NOT_ENABLED error (HTTP 400) with the message "Two-factor authentication is not enabled".
func NewTwoFactorNotEnabledError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTwoFactorNotEnabled,
		Message:    "Two-factor authentication is not enabled",
		StatusCode: http.StatusBadRequest,
	}
}

// NewTwoFactorInvalidError returns the TWO_FACTOR_INVALID error (HTTP 400) with the message "Two-factor authentication is invalid".
func NewTwoFactorInvalidError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTwoFactorInvalid,
		Message:    "Two-factor authentication is invalid",
		StatusCode: http.StatusBadRequest,
	}
}

// NewTwoFactorExpiredError returns the TWO_FACTOR_EXPIRED error (HTTP 400) with the message "Two-factor authentication has expired".
func NewTwoFactorExpiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTwoFactorExpired,
		Message:    "Two-factor authentication has expired",
		StatusCode: http.StatusBadRequest,
	}
}

// NewTwoFactorNotFoundError returns the TWO_FACTOR_NOT_FOUND error (HTTP 400) with the message "Two-factor authentication not found".
func NewTwoFactorNotFoundError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTwoFactorNotFound,
		Message:    "Two-factor authentication not found",
		StatusCode: http.StatusBadRequest,
	}
}

// NewTwoFactorAlreadyUsedError returns the TWO_FACTOR_ALREADY_USED error (HTTP 400) with the message "Two-factor authentication has already been used".
func NewTwoFactorAlreadyUsedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrTwoFactorAlreadyUsed,
		Message:    "Two-factor authentication has already been used",
		StatusCode: http.StatusBadRequest,
	}
}

// NewInvalidVerificationTokenError returns the INVALID_VERIFICATION_TOKEN error (HTTP 400) with the message "Invalid verification token".
func NewInvalidVerificationTokenError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidVerificationToken,
		Message:    "Invalid verification token",
		StatusCode: http.StatusBadRequest,
	}
}

// NewVerificationTokenExpiredError returns the VERIFICATION_TOKEN_EXPIRED error (HTTP 400) with the message "Verification token has expired".
func NewVerificationTokenExpiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrVerificationTokenExpired,
		Message:    "Verification token has expired",
		StatusCode: http.StatusBadRequest,
	}
}

// NewInvalidVerificationCodeError returns the INVALID_VERIFICATION_CODE error (HTTP 400) with the message "Invalid verification code".
func NewInvalidVerificationCodeError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrInvalidVerificationCode,
		Message:    "Invalid verification code",
		StatusCode: http.StatusBadRequest,
	}
}

// NewVerificationCodeExpiredError returns the VERIFICATION_CODE_EXPIRED error (HTTP 400) with the message "Verification code has expired".
func NewVerificationCodeExpiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrVerificationCodeExpired,
		Message:    "Verification code has expired",
		StatusCode: http.StatusBadRequest,
	}
}

// OAuth error factory functions

// NewOAuthProviderNotFoundError returns the OAUTH_PROVIDER_NOT_FOUND error (HTTP 400) with a message that names provider.
func NewOAuthProviderNotFoundError(provider string) *GoAuthError {
	return &GoAuthError{
		Code:       ErrOAuthProviderNotFound,
		Message:    "OAuth provider '" + provider + "' not found or not configured",
		StatusCode: http.StatusBadRequest,
	}
}

// NewOAuthProviderDisabledError returns the OAUTH_PROVIDER_DISABLED error (HTTP 400) with a message that names provider.
func NewOAuthProviderDisabledError(provider string) *GoAuthError {
	return &GoAuthError{
		Code:       ErrOAuthProviderDisabled,
		Message:    "OAuth provider '" + provider + "' is disabled",
		StatusCode: http.StatusBadRequest,
	}
}

// NewOAuthInvalidStateError returns the OAUTH_INVALID_STATE error (HTTP 400) with the message "Invalid OAuth state parameter".
func NewOAuthInvalidStateError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrOAuthInvalidState,
		Message:    "Invalid OAuth state parameter",
		StatusCode: http.StatusBadRequest,
	}
}

// NewOAuthStateExpiredError returns the OAUTH_STATE_EXPIRED error (HTTP 400) with the message "OAuth state has expired. Please try again.".
func NewOAuthStateExpiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrOAuthStateExpired,
		Message:    "OAuth state has expired. Please try again.",
		StatusCode: http.StatusBadRequest,
	}
}

// NewOAuthStateUsedError returns the OAUTH_STATE_USED error (HTTP 400) with the message "OAuth state has already been used".
func NewOAuthStateUsedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrOAuthStateUsed,
		Message:    "OAuth state has already been used",
		StatusCode: http.StatusBadRequest,
	}
}

// NewOAuthTokenExchangeError returns the OAUTH_TOKEN_EXCHANGE_FAILED error (HTTP 400) with the given message, or "Failed to exchange authorization code for tokens" when it is empty.
func NewOAuthTokenExchangeError(message string) *GoAuthError {
	if message == "" {
		message = "Failed to exchange authorization code for tokens"
	}
	return &GoAuthError{
		Code:       ErrOAuthTokenExchange,
		Message:    message,
		StatusCode: http.StatusBadRequest,
	}
}

// NewOAuthUserInfoError returns the OAUTH_USER_INFO_FAILED error (HTTP 400) with the given message, or "Failed to retrieve user information from OAuth provider" when it is empty.
func NewOAuthUserInfoError(message string) *GoAuthError {
	if message == "" {
		message = "Failed to retrieve user information from OAuth provider"
	}
	return &GoAuthError{
		Code:       ErrOAuthUserInfo,
		Message:    message,
		StatusCode: http.StatusBadRequest,
	}
}

// NewOAuthEmailExistsError returns the OAUTH_EMAIL_EXISTS error (HTTP 409) with the message "An account with this email already exists".
func NewOAuthEmailExistsError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrOAuthEmailExists,
		Message:    "An account with this email already exists",
		StatusCode: http.StatusConflict,
	}
}

// NewOAuthSignupDisabledError returns the OAUTH_SIGNUP_DISABLED error (HTTP 403) with the message "Signup via OAuth is disabled".
func NewOAuthSignupDisabledError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrOAuthSignupDisabled,
		Message:    "Signup via OAuth is disabled",
		StatusCode: http.StatusForbidden,
	}
}

// NewOAuthProviderError returns the OAUTH_PROVIDER_ERROR error (HTTP 400) with the given message, or "OAuth provider returned an error" when it is empty.
func NewOAuthProviderError(message string) *GoAuthError {
	if message == "" {
		message = "OAuth provider returned an error"
	}
	return &GoAuthError{
		Code:       ErrOAuthProviderError,
		Message:    message,
		StatusCode: http.StatusBadRequest,
	}
}

// NewOAuthNotLinkedError returns the OAUTH_NOT_LINKED error (HTTP 400) with a message that names provider.
func NewOAuthNotLinkedError(provider string) *GoAuthError {
	return &GoAuthError{
		Code:       ErrOAuthNotLinked,
		Message:    "OAuth provider '" + provider + "' is not linked to this account",
		StatusCode: http.StatusBadRequest,
	}
}

// NewOAuthAlreadyLinkedError returns the OAUTH_ALREADY_LINKED error (HTTP 409) with a message that names provider.
func NewOAuthAlreadyLinkedError(provider string) *GoAuthError {
	return &GoAuthError{
		Code:       ErrOAuthAlreadyLinked,
		Message:    "OAuth provider '" + provider + "' is already linked to this account",
		StatusCode: http.StatusConflict,
	}
}

// NewOAuthEmailRequiredError returns the OAUTH_EMAIL_REQUIRED error (HTTP 400) with the message "Email address is required from OAuth provider".
func NewOAuthEmailRequiredError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrOAuthEmailRequired,
		Message:    "Email address is required from OAuth provider",
		StatusCode: http.StatusBadRequest,
	}
}

// NewOAuthEmailUnverifiedError rejects signup from a provider identity whose
// email address the provider has not verified.
func NewOAuthEmailUnverifiedError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrOAuthEmailUnverified,
		Message:    "The identity provider has not verified this email address",
		StatusCode: http.StatusForbidden,
	}
}

// NewOAuthAccountLinkingDisabledError returns the OAUTH_ACCOUNT_LINKING_DISABLED error (HTTP 403) with the message "Account linking via OAuth is disabled".
func NewOAuthAccountLinkingDisabledError() *GoAuthError {
	return &GoAuthError{
		Code:       ErrOAuthAccountLinkingDisabled,
		Message:    "Account linking via OAuth is disabled",
		StatusCode: http.StatusForbidden,
	}
}

// Organization error factory functions

// NewOrgNotFoundError returns the ORG_NOT_FOUND error (HTTP 404) with the message "Organization not found".
func NewOrgNotFoundError() *GoAuthError {
	return &GoAuthError{Code: ErrOrgNotFound, Message: "Organization not found", StatusCode: http.StatusNotFound}
}

// NewOrgSlugTakenError returns the ORG_SLUG_TAKEN error (HTTP 409) with the message "Organization slug is already taken".
func NewOrgSlugTakenError() *GoAuthError {
	return &GoAuthError{Code: ErrOrgSlugTaken, Message: "Organization slug is already taken", StatusCode: http.StatusConflict}
}

// NewOrgMemberExistsError returns the ORG_MEMBER_EXISTS error (HTTP 409) with the message "User is already a member of this organization".
func NewOrgMemberExistsError() *GoAuthError {
	return &GoAuthError{Code: ErrOrgMemberExists, Message: "User is already a member of this organization", StatusCode: http.StatusConflict}
}

// NewOrgMemberNotFoundError returns the ORG_MEMBER_NOT_FOUND error (HTTP 404) with the message "Organization member not found".
func NewOrgMemberNotFoundError() *GoAuthError {
	return &GoAuthError{Code: ErrOrgMemberNotFound, Message: "Organization member not found", StatusCode: http.StatusNotFound}
}

// NewOrgNotMemberError returns the ORG_NOT_MEMBER error (HTTP 403) with the message "You are not a member of this organization".
func NewOrgNotMemberError() *GoAuthError {
	return &GoAuthError{Code: ErrOrgNotMember, Message: "You are not a member of this organization", StatusCode: http.StatusForbidden}
}

// NewOrgInsufficientRoleError returns the ORG_INSUFFICIENT_ROLE error (HTTP 403) with the message "Insufficient role for this operation".
func NewOrgInsufficientRoleError() *GoAuthError {
	return &GoAuthError{Code: ErrOrgInsufficientRole, Message: "Insufficient role for this operation", StatusCode: http.StatusForbidden}
}

// NewOrgCannotRemoveOwnerError returns the ORG_CANNOT_REMOVE_OWNER error (HTTP 403) with the message "Cannot remove the organization owner".
func NewOrgCannotRemoveOwnerError() *GoAuthError {
	return &GoAuthError{Code: ErrOrgCannotRemoveOwner, Message: "Cannot remove the organization owner", StatusCode: http.StatusForbidden}
}

// NewOrgMaxMembersError returns the ORG_MAX_MEMBERS error (HTTP 403) with the message "Organization has reached the maximum number of members".
func NewOrgMaxMembersError() *GoAuthError {
	return &GoAuthError{Code: ErrOrgMaxMembers, Message: "Organization has reached the maximum number of members", StatusCode: http.StatusForbidden}
}

// NewInvitationNotFoundError returns the INVITATION_NOT_FOUND error (HTTP 404) with the message "Invitation not found".
func NewInvitationNotFoundError() *GoAuthError {
	return &GoAuthError{Code: ErrInvitationNotFound, Message: "Invitation not found", StatusCode: http.StatusNotFound}
}

// NewInvitationExpiredError returns the INVITATION_EXPIRED error (HTTP 400) with the message "Invitation has expired".
func NewInvitationExpiredError() *GoAuthError {
	return &GoAuthError{Code: ErrInvitationExpired, Message: "Invitation has expired", StatusCode: http.StatusBadRequest}
}

// NewInvitationExistsError returns the INVITATION_ALREADY_EXISTS error (HTTP 409) with the message "A pending invitation already exists for this email".
func NewInvitationExistsError() *GoAuthError {
	return &GoAuthError{Code: ErrInvitationExists, Message: "A pending invitation already exists for this email", StatusCode: http.StatusConflict}
}

// NewInvitationEmailMismatchError returns the INVITATION_EMAIL_MISMATCH error (HTTP 403) with the message "Your email does not match the invitation".
func NewInvitationEmailMismatchError() *GoAuthError {
	return &GoAuthError{Code: ErrInvitationEmailMismatch, Message: "Your email does not match the invitation", StatusCode: http.StatusForbidden}
}

// NewRateLimitExceededError reports that the client exceeded a rate-limit
// rule. retryAfter is rounded up to whole seconds in Details.
func NewRateLimitExceededError(retryAfter time.Duration) *GoAuthError {
	seconds := int64(retryAfter / time.Second)
	if retryAfter%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	return &GoAuthError{
		Code:       ErrRateLimitExceeded,
		Message:    "Too many requests. Please retry later.",
		StatusCode: http.StatusTooManyRequests,
		Details:    map[string]any{"retry_after_seconds": seconds},
	}
}
