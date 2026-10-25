package dto

import (
	"encoding/json"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

// BeginRegistrationResponse contains the WebAuthn creation options returned to
// the browser, plus an opaque ChallengeToken the client must echo back on finish.
type BeginRegistrationResponse struct {
	ChallengeToken string                                      `json:"challenge_token"`
	PublicKey      protocol.PublicKeyCredentialCreationOptions `json:"public_key"`
}

// FinishRegistrationRequest carries the WebAuthn attestation response produced
// by navigator.credentials.create() back to the server.
type FinishRegistrationRequest struct {
	ChallengeToken     string          `json:"challenge_token"`
	CredentialResponse json.RawMessage `json:"credential_response"`
	Name               string          `json:"name"`
}

// BeginLoginResponse returns assertion options for navigator.credentials.get().
type BeginLoginResponse struct {
	ChallengeToken string                                     `json:"challenge_token"`
	PublicKey      protocol.PublicKeyCredentialRequestOptions `json:"public_key"`
}

// FinishLoginRequest carries the WebAuthn assertion response back to the server.
type FinishLoginRequest struct {
	ChallengeToken     string          `json:"challenge_token"`
	CredentialResponse json.RawMessage `json:"credential_response"`
}

// PasskeySummary is the public-facing view of a stored passkey.
type PasskeySummary struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Transports []string   `json:"transports,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// RenameRequest is the body of the rename endpoint.
type RenameRequest struct {
	Name string `json:"name"`
}
