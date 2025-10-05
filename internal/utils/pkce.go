package utils

import (
	"crypto/sha256"
	"encoding/base64"
)

func GeneratePKCECodeChallenge(verifier string) (string, error) {
	// Hash the verifier with SHA256
	hash := sha256.Sum256([]byte(verifier))

	// Base64 URL encode the hash
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return challenge, nil
}