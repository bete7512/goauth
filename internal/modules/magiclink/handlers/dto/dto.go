package dto

import "fmt"

// MagicLinkSendRequest is the request body for POST /magic-link/send and /magic-link/resend.
type MagicLinkSendRequest struct {
	Email string `json:"email"`
}

// Validate validates the send request.
func (r *MagicLinkSendRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	return nil
}

// MagicLinkVerifyByCodeRequest is the request body for POST /magic-link/verify-code.
type MagicLinkVerifyByCodeRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// Validate validates the verify-by-code request.
func (r *MagicLinkVerifyByCodeRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	if r.Code == "" {
		return fmt.Errorf("code is required")
	}
	return nil
}
