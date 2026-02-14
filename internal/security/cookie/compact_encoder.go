package cookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/types"
)

var _ CookieEncoder = (*compactEncoder)(nil)

// compactEncoder uses base64url(JSON) + "." + HMAC-SHA256.
// Smallest cookie size (~200 bytes), fastest encode/decode.
type compactEncoder struct {
	signingKey []byte
}

func newCompactEncoder(key string) *compactEncoder {
	return &compactEncoder{signingKey: []byte(key)}
}

func (e *compactEncoder) Encode(data *types.SessionCookieData) (string, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	encoded := base64.RawURLEncoding.EncodeToString(payload)
	sig := e.sign([]byte(encoded))
	sigEncoded := base64.RawURLEncoding.EncodeToString(sig)

	return encoded + "." + sigEncoded, nil
}

func (e *compactEncoder) Decode(cookieValue string) (*types.SessionCookieData, error) {
	parts := strings.SplitN(cookieValue, ".", 2)
	if len(parts) != 2 {
		return nil, ErrInvalidFormat
	}

	payloadPart := parts[0]
	sigPart := parts[1]

	// Verify HMAC
	expectedSig := e.sign([]byte(payloadPart))
	actualSig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil {
		return nil, ErrInvalidFormat
	}
	if !hmac.Equal(expectedSig, actualSig) {
		return nil, ErrInvalidHMAC
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return nil, ErrInvalidFormat
	}

	var data types.SessionCookieData
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, ErrInvalidFormat
	}

	// Check expiry
	if time.Now().Unix() > data.ExpiresAt {
		return nil, ErrExpired
	}

	return &data, nil
}

func (e *compactEncoder) MaxSize() int {
	return 250
}

func (e *compactEncoder) EncodingType() types.CookieEncoding {
	return types.CookieEncodingCompact
}

func (e *compactEncoder) sign(data []byte) []byte {
	mac := hmac.New(sha256.New, e.signingKey)
	mac.Write(data)
	return mac.Sum(nil)
}
