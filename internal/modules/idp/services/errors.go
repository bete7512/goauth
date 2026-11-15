package services

import (
	"net/http"

	"github.com/bete7512/goauth/pkg/types"
)

// OAuth and OpenID Connect protocol error codes (RFC 6749 sections 4.1.2.1
// and 5.2, RFC 6750 section 3.1, OpenID Connect Core section 3.1.2.6). The
// protocol endpoints return a *types.GoAuthError whose Code is one of these,
// and the handlers render it as {"error": ..., "error_description": ...}.
const (
	CodeInvalidRequest          types.ErrorCode = "invalid_request"
	CodeInvalidClient           types.ErrorCode = "invalid_client"
	CodeInvalidGrant            types.ErrorCode = "invalid_grant"
	CodeUnauthorizedClient      types.ErrorCode = "unauthorized_client"
	CodeUnsupportedGrantType    types.ErrorCode = "unsupported_grant_type"
	CodeUnsupportedResponseType types.ErrorCode = "unsupported_response_type"
	CodeInvalidScope            types.ErrorCode = "invalid_scope"
	CodeAccessDenied            types.ErrorCode = "access_denied"
	CodeServerError             types.ErrorCode = "server_error"
	CodeInvalidToken            types.ErrorCode = "invalid_token"
	CodeInsufficientScope       types.ErrorCode = "insufficient_scope"
	CodeInteractionRequired     types.ErrorCode = "interaction_required"
	CodeRequestNotSupported     types.ErrorCode = "request_not_supported"
	CodeRequestURINotSupported  types.ErrorCode = "request_uri_not_supported"
)

func oauthError(code types.ErrorCode, status int, description string) *types.GoAuthError {
	return &types.GoAuthError{Code: code, Message: description, StatusCode: status}
}

func errInvalidRequest(description string) *types.GoAuthError {
	return oauthError(CodeInvalidRequest, http.StatusBadRequest, description)
}

// errInvalidClient is deliberately vague: it must not reveal whether the
// client exists or which part of its authentication failed.
func errInvalidClient() *types.GoAuthError {
	return oauthError(CodeInvalidClient, http.StatusUnauthorized, "Client authentication failed")
}

func errInvalidGrant(description string) *types.GoAuthError {
	if description == "" {
		description = "The grant is invalid, expired or revoked"
	}
	return oauthError(CodeInvalidGrant, http.StatusBadRequest, description)
}

func errInvalidScope(description string) *types.GoAuthError {
	return oauthError(CodeInvalidScope, http.StatusBadRequest, description)
}

// errInvalidToken answers a UserInfo request whose access token is missing,
// unknown, expired or revoked. It says nothing about which.
func errInvalidToken() *types.GoAuthError {
	return oauthError(CodeInvalidToken, http.StatusUnauthorized, "The access token is invalid or has expired")
}

// errServer hides the cause from the client; the caller logs it.
func errServer(cause error) *types.GoAuthError {
	return oauthError(CodeServerError, http.StatusInternalServerError, "The server encountered an unexpected error").Wrap(cause)
}
