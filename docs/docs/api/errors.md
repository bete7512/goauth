---
id: errors
title: Error Reference
sidebar_label: Errors
sidebar_position: 3
---

# Error Reference

GoAuth uses structured error responses across all modules. Every error returned by the library is a `*types.GoAuthError`, providing a machine-readable code, a human-readable message, and an HTTP status code.

## GoAuthError Struct

```go
type GoAuthError struct {
    Code       ErrorCode `json:"code"`
    Message    string    `json:"message"`
    StatusCode int       `json:"-"`
    Details    any       `json:"details,omitempty"`
    Err        error     `json:"-"`
}
```

| Field | Type | JSON | Description |
|---|---|---|---|
| `Code` | `ErrorCode` (string) | `"code"` | Machine-readable error code (e.g. `"USER_NOT_FOUND"`) |
| `Message` | `string` | `"message"` | Human-readable error description |
| `StatusCode` | `int` | hidden (`json:"-"`) | HTTP status code used in the response |
| `Details` | `any` | `"details"` (omitted if nil) | Additional context (e.g. 2FA challenge data) |
| `Err` | `error` | hidden (`json:"-"`) | Wrapped underlying error for debugging |

### Methods

**`Error() string`** -- Implements the `error` interface. Returns `Message` if no wrapped error, or `"Message: wrapped error"` if one exists.

**`Wrap(err error) *GoAuthError`** -- Sets the underlying error and returns the same `GoAuthError` for chaining. Use this to attach a root cause while preserving the structured error:

```go
return types.NewDatabaseError().Wrap(err)
```

**`Unwrap() error`** -- Returns the underlying error, enabling `errors.Is()` and `errors.As()` to traverse the error chain:

```go
if errors.Is(authErr.Unwrap(), sql.ErrNoRows) {
    // handle missing row
}
```

### Constructor

```go
func NewGoAuthError(code ErrorCode, message string, statusCode int) *GoAuthError
```

Creates a custom `GoAuthError` with any code, message, and status code. Most common errors have dedicated factory functions (listed below).

## Standard Error Response

All error responses follow this JSON shape:

```json
{
  "code": "ERROR_CODE",
  "message": "Human-readable description of the error",
  "details": null
}
```

The `details` field is omitted from the response when nil. It is populated for specific errors like `TWO_FACTOR_REQUIRED`, where it carries challenge metadata.

The HTTP status code is set on the response header, not in the JSON body.

---

## Error Codes by Category

### User Errors

| Constant | Code | HTTP Status | Default Message |
|---|---|---|---|
| `ErrUserNotFound` | `USER_NOT_FOUND` | 404 Not Found | User not found |
| `ErrUserAlreadyExists` | `USER_ALREADY_EXISTS` | 409 Conflict | User with this email already exists |
| `ErrUserNotActive` | `USER_NOT_ACTIVE` | 403 Forbidden | User account is not active |
| `ErrUserBlocked` | `USER_BLOCKED` | 403 Forbidden | User account is blocked |
| `ErrEmailNotVerified` | `EMAIL_NOT_VERIFIED` | 403 Forbidden | Email address not verified |
| `ErrPhoneNotVerified` | `PHONE_NOT_VERIFIED` | 403 Forbidden | Phone number not verified |
| `ErrAccountDeactivated` | `ACCOUNT_DEACTIVATED` | 403 Forbidden | Account has been deactivated |
| `ErrEmailAlreadyVerified` | `EMAIL_ALREADY_VERIFIED` | 400 Bad Request | Email address already verified |
| `ErrPhoneAlreadyVerified` | `PHONE_ALREADY_VERIFIED` | 400 Bad Request | Phone number already verified |
| `ErrPhoneAlreadyInUse` | `PHONE_ALREADY_IN_USE` | 400 Bad Request | Phone number already in use |
| `ErrUsernameAlreadyExists` | `USERNAME_ALREADY_EXISTS` | 400 Bad Request | Username already exists |

### Authentication Errors

| Constant | Code | HTTP Status | Default Message |
|---|---|---|---|
| `ErrInvalidCredentials` | `INVALID_CREDENTIALS` | 401 Unauthorized | Invalid email or password |
| `ErrInvalidToken` | `INVALID_TOKEN` | 401 Unauthorized | Invalid or expired token |
| `ErrTokenExpired` | `TOKEN_EXPIRED` | 401 Unauthorized | Token has expired |
| `ErrTokenNotFound` | `TOKEN_NOT_FOUND` | 400 Bad Request | Token not found |
| `ErrTokenAlreadyUsed` | `TOKEN_ALREADY_USED` | 400 Bad Request | Token already used |
| `ErrInvalidRefreshToken` | `INVALID_REFRESH_TOKEN` | 401 Unauthorized | Invalid refresh token |
| `ErrAccountLocked` | `ACCOUNT_LOCKED` | 423 Locked | Account is temporarily locked due to too many failed attempts |
| `ErrPasswordExpired` | `PASSWORD_EXPIRED` | 401 Unauthorized | Password has expired |

### Session Errors

| Constant | Code | HTTP Status | Default Message |
|---|---|---|---|
| `ErrInvalidSession` | `INVALID_SESSION` | 401 Unauthorized | Invalid session |
| `ErrSessionNotFound` | `SESSION_NOT_FOUND` | 404 Not Found | Session not found |
| `ErrSessionExpired` | `SESSION_EXPIRED` | 401 Unauthorized | Session has expired |
| `ErrSessionInvalid` | `SESSION_INVALID` | 401 Unauthorized | Session is invalid |

### Validation Errors

| Constant | Code | HTTP Status | Default Message |
|---|---|---|---|
| `ErrInvalidEmail` | `INVALID_EMAIL` | 400 Bad Request | Invalid email format |
| `ErrInvalidPassword` | `INVALID_PASSWORD` | 400 Bad Request | Invalid password format |
| `ErrInvalidPhone` | `INVALID_PHONE` | 400 Bad Request | Invalid phone number format |
| `ErrMissingFields` | `MISSING_FIELDS` | 400 Bad Request | Missing required fields |
| `ErrInvalidRequestBody` | `INVALID_REQUEST_BODY` | 400 Bad Request | *(custom message)* |
| `ErrInvalidJSON` | `INVALID_JSON` | 400 Bad Request | Invalid JSON format |
| `ErrValidation` | `VALIDATION_ERROR` | *(not assigned by default)* | *(not assigned by default)* |
| `ErrInvalidRequestIP` | `INVALID_REQUEST_IP` | *(not assigned by default)* | *(not assigned by default)* |

`ErrMissingFields` accepts a fields parameter: when provided, the message becomes `"Missing required fields: email, password"`.

`ErrInvalidRequestBody` is used by `NewValidationError(message)` which accepts a custom message.

### Authorization Errors

| Constant | Code | HTTP Status | Default Message |
|---|---|---|---|
| `ErrUnauthorized` | `UNAUTHORIZED` | 401 Unauthorized | Unauthorized access |
| `ErrForbidden` | `FORBIDDEN` | 403 Forbidden | Access forbidden |
| `ErrInvalidCSRF` | `INVALID_CSRF` | 403 Forbidden | Invalid CSRF token |
| `ErrCaptchaRequired` | `CAPTCHA_REQUIRED` | 403 Forbidden | Captcha token required |
| `ErrCaptchaFailed` | `CAPTCHA_FAILED` | 403 Forbidden | Captcha verification failed |

### Two-Factor Authentication Errors

| Constant | Code | HTTP Status | Default Message |
|---|---|---|---|
| `ErrTwoFactorRequired` | `TWO_FACTOR_REQUIRED` | 200 OK | Two-factor authentication required |
| `ErrTwoFactorAlreadyEnabled` | `TWO_FACTOR_ALREADY_ENABLED` | 400 Bad Request | Two-factor authentication is already enabled |
| `ErrTwoFactorNotEnabled` | `TWO_FACTOR_NOT_ENABLED` | 400 Bad Request | Two-factor authentication is not enabled |
| `ErrTwoFactorNotFound` | `TWO_FACTOR_NOT_FOUND` | 400 Bad Request | Two-factor authentication not found |
| `ErrTwoFactorInvalid` | `TWO_FACTOR_INVALID` | 400 Bad Request | Two-factor authentication is invalid |
| `ErrTwoFactorExpired` | `TWO_FACTOR_EXPIRED` | 400 Bad Request | Two-factor authentication has expired |
| `ErrTwoFactorAlreadyUsed` | `TWO_FACTOR_ALREADY_USED` | 400 Bad Request | Two-factor authentication has already been used |

`TWO_FACTOR_REQUIRED` uses HTTP 200 intentionally -- it is not an error but a challenge response. The `details` field carries challenge metadata (e.g. available 2FA methods).

### OAuth Errors

| Constant | Code | HTTP Status | Default Message |
|---|---|---|---|
| `ErrOAuthProviderNotFound` | `OAUTH_PROVIDER_NOT_FOUND` | 400 Bad Request | OAuth provider '&lt;provider&gt;' not found or not configured |
| `ErrOAuthProviderDisabled` | `OAUTH_PROVIDER_DISABLED` | 400 Bad Request | OAuth provider '&lt;provider&gt;' is disabled |
| `ErrOAuthInvalidState` | `OAUTH_INVALID_STATE` | 400 Bad Request | Invalid OAuth state parameter |
| `ErrOAuthStateExpired` | `OAUTH_STATE_EXPIRED` | 400 Bad Request | OAuth state has expired. Please try again. |
| `ErrOAuthStateUsed` | `OAUTH_STATE_USED` | 400 Bad Request | OAuth state has already been used |
| `ErrOAuthTokenExchange` | `OAUTH_TOKEN_EXCHANGE_FAILED` | 400 Bad Request | Failed to exchange authorization code for tokens |
| `ErrOAuthUserInfo` | `OAUTH_USER_INFO_FAILED` | 400 Bad Request | Failed to retrieve user information from OAuth provider |
| `ErrOAuthEmailExists` | `OAUTH_EMAIL_EXISTS` | 409 Conflict | An account with this email already exists |
| `ErrOAuthSignupDisabled` | `OAUTH_SIGNUP_DISABLED` | 403 Forbidden | Signup via OAuth is disabled |
| `ErrOAuthProviderError` | `OAUTH_PROVIDER_ERROR` | 400 Bad Request | OAuth provider returned an error |
| `ErrOAuthNotLinked` | `OAUTH_NOT_LINKED` | 400 Bad Request | OAuth provider '&lt;provider&gt;' is not linked to this account |
| `ErrOAuthAlreadyLinked` | `OAUTH_ALREADY_LINKED` | 409 Conflict | OAuth provider '&lt;provider&gt;' is already linked to this account |
| `ErrOAuthEmailRequired` | `OAUTH_EMAIL_REQUIRED` | 400 Bad Request | Email address is required from OAuth provider |
| `ErrOAuthAccountLinkingDisabled` | `OAUTH_ACCOUNT_LINKING_DISABLED` | 403 Forbidden | Account linking via OAuth is disabled |

Some OAuth factory functions accept a `provider` or `message` parameter that is interpolated into the default message.

### Organization Errors

| Constant | Code | HTTP Status | Default Message |
|---|---|---|---|
| `ErrOrgNotFound` | `ORG_NOT_FOUND` | 404 Not Found | Organization not found |
| `ErrOrgSlugTaken` | `ORG_SLUG_TAKEN` | 409 Conflict | Organization slug is already taken |
| `ErrOrgMemberExists` | `ORG_MEMBER_EXISTS` | 409 Conflict | User is already a member of this organization |
| `ErrOrgMemberNotFound` | `ORG_MEMBER_NOT_FOUND` | 404 Not Found | Organization member not found |
| `ErrOrgNotMember` | `ORG_NOT_MEMBER` | 403 Forbidden | You are not a member of this organization |
| `ErrOrgInsufficientRole` | `ORG_INSUFFICIENT_ROLE` | 403 Forbidden | Insufficient role for this operation |
| `ErrOrgCannotRemoveOwner` | `ORG_CANNOT_REMOVE_OWNER` | 403 Forbidden | Cannot remove the organization owner |
| `ErrOrgMaxMembers` | `ORG_MAX_MEMBERS` | 403 Forbidden | Organization has reached the maximum number of members |
| `ErrInvitationNotFound` | `INVITATION_NOT_FOUND` | 404 Not Found | Invitation not found |
| `ErrInvitationExpired` | `INVITATION_EXPIRED` | 400 Bad Request | Invitation has expired |
| `ErrInvitationExists` | `INVITATION_ALREADY_EXISTS` | 409 Conflict | A pending invitation already exists for this email |
| `ErrInvitationEmailMismatch` | `INVITATION_EMAIL_MISMATCH` | 403 Forbidden | Your email does not match the invitation |

### Verification Errors

| Constant | Code | HTTP Status | Default Message |
|---|---|---|---|
| `ErrInvalidVerificationToken` | `INVALID_VERIFICATION_TOKEN` | 400 Bad Request | Invalid verification token |
| `ErrVerificationTokenExpired` | `VERIFICATION_TOKEN_EXPIRED` | 400 Bad Request | Verification token has expired |
| `ErrInvalidVerificationCode` | `INVALID_VERIFICATION_CODE` | 400 Bad Request | Invalid verification code |
| `ErrVerificationCodeExpired` | `VERIFICATION_CODE_EXPIRED` | 400 Bad Request | Verification code has expired |

### System Errors

| Constant | Code | HTTP Status | Default Message |
|---|---|---|---|
| `ErrInternalError` | `INTERNAL_ERROR` | 500 Internal Server Error | An unexpected error occurred |
| `ErrDatabaseError` | `DATABASE_ERROR` | 500 Internal Server Error | Database operation failed |
| `ErrEmailSendFailed` | `EMAIL_SEND_FAILED` | 500 Internal Server Error | Failed to send email |
| `ErrSmsSendFailed` | `SMS_SEND_FAILED` | 500 Internal Server Error | Failed to send SMS |
| `ErrConfigurationError` | `CONFIGURATION_ERROR` | 500 Internal Server Error | Configuration error |
| `ErrMethodNotAllowed` | `METHOD_NOT_ALLOWED` | 405 Method Not Allowed | Method not allowed |

### Other Errors

| Constant | Code | HTTP Status | Default Message |
|---|---|---|---|
| `ErrUnknown` | `UNKNOWN_ERROR` | 500 Internal Server Error | An unexpected error occurred |
| `ErrCustom` | `CUSTOM_ERROR` | *(caller-defined)* | *(caller-defined)* |

`NewCustomError(message)` creates an error with no HTTP status code set -- the caller is expected to set `StatusCode` before returning it to an HTTP handler.

---

## Handling Errors in Client Code

### Checking Error Codes

```go
if authErr != nil && authErr.Code == types.ErrUserNotFound {
    // handle user not found
}
```

### Wrapping Errors

```go
user, err := db.FindByEmail(ctx, email)
if err != nil {
    return types.NewDatabaseError().Wrap(err)
}
```

### Using errors.Is with Wrapped Errors

```go
authErr := someOperation()
if authErr != nil && errors.Is(authErr, sql.ErrNoRows) {
    // the underlying cause was a missing DB row
}
```

### Factory Functions with Parameters

Several factory functions accept parameters for dynamic messages:

```go
types.NewMissingFieldsError("email, password")
// Message: "Missing required fields: email, password"

types.NewOAuthProviderNotFoundError("github")
// Message: "OAuth provider 'github' not found or not configured"

types.NewInternalError("failed to hash password")
// Message: "failed to hash password"

types.NewValidationError("password must be at least 8 characters")
// Message: "password must be at least 8 characters"
```
