package responseErrors

const (
	// Token related errors
	ErrInvalidToken        = "invalid or expired verification token"
	ErrTokenAlreadyUsed    = "verification token already used"
	ErrTokenExpired        = "token has expired"
	ErrTokenNotFound       = "token not found"
	ErrInvalidRefreshToken = "invalid refresh token"

	// User related errors
	ErrUserNotFound         = "user not found"
	ErrUserAlreadyExists    = "user already exists"
	ErrUserNotActive        = "user account is not active"
	ErrUserBlocked          = "user account is blocked"
	ErrEmailNotVerified     = "email address not verified"
	ErrEmailAlreadyVerified = "email address already verified"
	ErrPhoneAlreadyVerified = "phone number already verified"
	// Authentication errors
	ErrInvalidCredentials = "invalid email or password"
	ErrAccountLocked      = "account is temporarily locked"
	ErrPasswordExpired    = "password has expired"
	ErrInvalidEmail       = "invalid email format"
	ErrInvalidPassword    = "invalid password format"

	// Request/Response errors
	ErrMethodNotAllowed   = "method not allowed"
	ErrMissingFields      = "missing required fields"
	ErrInvalidRequestBody = "invalid request body"
	ErrInvalidJSON        = "invalid json format"

	// Security errors
	ErrTooManyRequests = "too many verification attempts"
	ErrInvalidCSRF     = "invalid csrf token"
	ErrUnauthorized    = "unauthorized access"
	ErrForbidden       = "access forbidden"

	// System errors
	ErrInternalError      = "internal server error"
	ErrDatabaseError      = "database operation failed"
	ErrEmailSendFailed    = "failed to send email"
	ErrConfigurationError = "configuration error"
)

// HTTP Status Code mappings
var ErrorStatusCodes = map[string]int{
	ErrInvalidToken:        400,
	ErrTokenAlreadyUsed:    400,
	ErrTokenExpired:        400,
	ErrTokenNotFound:       400,
	ErrInvalidRefreshToken: 401,

	ErrUserNotFound:      404,
	ErrUserAlreadyExists: 409,
	ErrUserNotActive:     403,
	ErrUserBlocked:       403,
	ErrEmailNotVerified:  403,

	ErrInvalidCredentials: 401,
	ErrAccountLocked:      423,
	ErrPasswordExpired:    401,
	ErrInvalidEmail:       400,
	ErrInvalidPassword:    400,

	ErrMethodNotAllowed:   405,
	ErrMissingFields:      400,
	ErrInvalidRequestBody: 400,
	ErrInvalidJSON:        400,

	ErrTooManyRequests: 429,
	ErrInvalidCSRF:     403,
	ErrUnauthorized:    401,
	ErrForbidden:       403,

	ErrInternalError:      500,
	ErrDatabaseError:      500,
	ErrEmailSendFailed:    500,
	ErrConfigurationError: 500,
}

// GetStatusCode returns the HTTP status code for an error message
func GetStatusCode(errMsg string) int {
	if code, exists := ErrorStatusCodes[errMsg]; exists {
		return code
	}
	return 500 // Default to internal server error
}
