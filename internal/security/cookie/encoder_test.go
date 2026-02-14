package cookie

import (
	"strings"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
)

type EncoderSuite struct {
	suite.Suite
	encoders map[string]CookieEncoder
}

func TestEncoderSuite(t *testing.T) {
	suite.Run(t, new(EncoderSuite))
}

func (s *EncoderSuite) SetupTest() {
	key := "test-secret-key-for-session-cookies"
	s.encoders = map[string]CookieEncoder{
		"compact": newCompactEncoder(key),
		"jwt":     newJWTEncoder(key),
	}
}

func (s *EncoderSuite) validPayload() *types.SessionCookieData {
	return &types.SessionCookieData{
		SessionID: "sess-123-abc",
		UserID:    "user-456-def",
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
	}
}

func (s *EncoderSuite) TestRoundTrip() {
	for name, enc := range s.encoders {
		s.Run(name, func() {
			data := s.validPayload()
			encoded, err := enc.Encode(data)
			s.NoError(err)
			s.NotEmpty(encoded)

			decoded, err := enc.Decode(encoded)
			s.NoError(err)
			s.Equal(data.SessionID, decoded.SessionID)
			s.Equal(data.UserID, decoded.UserID)
			s.Equal(data.ExpiresAt, decoded.ExpiresAt)
			s.Equal(data.IssuedAt, decoded.IssuedAt)
		})
	}
}

func (s *EncoderSuite) TestExpiredCookie() {
	for name, enc := range s.encoders {
		s.Run(name, func() {
			data := &types.SessionCookieData{
				SessionID: "sess-123",
				UserID:    "user-456",
				ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
				IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
			}
			encoded, err := enc.Encode(data)
			s.NoError(err)

			_, err = enc.Decode(encoded)
			s.ErrorIs(err, ErrExpired)
		})
	}
}

func (s *EncoderSuite) TestTamperedSignature() {
	for name, enc := range s.encoders {
		s.Run(name, func() {
			data := s.validPayload()
			encoded, err := enc.Encode(data)
			s.NoError(err)

			// Flip the last character of the signature
			lastChar := encoded[len(encoded)-1]
			var replacement byte
			if lastChar == 'a' {
				replacement = 'b'
			} else {
				replacement = 'a'
			}
			tampered := encoded[:len(encoded)-1] + string(replacement)

			_, err = enc.Decode(tampered)
			s.Error(err)
			s.True(err == ErrInvalidHMAC || err == ErrInvalidFormat,
				"expected ErrInvalidHMAC or ErrInvalidFormat, got %v", err)
		})
	}
}

func (s *EncoderSuite) TestTamperedPayload() {
	// Only applicable to compact encoder (JWT payload is integrity-protected differently)
	enc := s.encoders["compact"]
	data := s.validPayload()
	encoded, err := enc.Encode(data)
	s.NoError(err)

	// Replace user ID in the base64-encoded payload
	parts := strings.SplitN(encoded, ".", 2)
	s.Require().Len(parts, 2)

	// Modify payload part while keeping signature
	tampered := parts[0] + "x" + "." + parts[1]
	_, err = enc.Decode(tampered)
	s.ErrorIs(err, ErrInvalidHMAC)
}

func (s *EncoderSuite) TestMalformedInput() {
	for name, enc := range s.encoders {
		s.Run(name, func() {
			cases := []string{"", "no-dot-here", "....", "abc.def.ghi"}
			for _, input := range cases {
				_, err := enc.Decode(input)
				s.Error(err, "expected error for input: %q", input)
			}
		})
	}
}

func (s *EncoderSuite) TestDifferentKeyCannotDecode() {
	for name, enc := range s.encoders {
		s.Run(name, func() {
			data := s.validPayload()
			encoded, err := enc.Encode(data)
			s.NoError(err)

			// Create decoder with a different key
			var other CookieEncoder
			switch name {
			case "compact":
				other = newCompactEncoder("completely-different-key")
			case "jwt":
				other = newJWTEncoder("completely-different-key")
			}

			_, err = other.Decode(encoded)
			s.Error(err)
		})
	}
}

func (s *EncoderSuite) TestCrossEncoderRejection() {
	compact := s.encoders["compact"]
	jwtEnc := s.encoders["jwt"]
	data := s.validPayload()

	// Compact value cannot be decoded by JWT encoder
	compactEncoded, err := compact.Encode(data)
	s.NoError(err)
	_, err = jwtEnc.Decode(compactEncoded)
	s.Error(err)

	// JWT value cannot be decoded by compact encoder
	jwtEncoded, err := jwtEnc.Encode(data)
	s.NoError(err)
	_, err = compact.Decode(jwtEncoded)
	s.Error(err)
}

func (s *EncoderSuite) TestMaxSize() {
	for name, enc := range s.encoders {
		s.Run(name, func() {
			s.Greater(enc.MaxSize(), 0)
		})
	}
}

func (s *EncoderSuite) TestEncodingType() {
	s.Equal(types.CookieEncodingCompact, s.encoders["compact"].EncodingType())
	s.Equal(types.CookieEncodingJWT, s.encoders["jwt"].EncodingType())
}

func (s *EncoderSuite) TestNewEncoderFactory() {
	key := "test-key"

	// Default (empty string) returns compact
	enc := NewEncoder("", key)
	s.Equal(types.CookieEncodingCompact, enc.EncodingType())

	// Explicit compact
	enc = NewEncoder(types.CookieEncodingCompact, key)
	s.Equal(types.CookieEncodingCompact, enc.EncodingType())

	// Explicit JWT
	enc = NewEncoder(types.CookieEncodingJWT, key)
	s.Equal(types.CookieEncodingJWT, enc.EncodingType())

	// Unknown encoding panics
	s.Panics(func() {
		NewEncoder("unknown", key)
	})
}

func (s *EncoderSuite) TestEncodedValueFitsInCookie() {
	for name, enc := range s.encoders {
		s.Run(name, func() {
			data := s.validPayload()
			encoded, err := enc.Encode(data)
			s.NoError(err)
			// Browser cookie limit is 4096 bytes
			s.Less(len(encoded), 4096)
			// Should be within the declared max size
			s.LessOrEqual(len(encoded), enc.MaxSize())
		})
	}
}
