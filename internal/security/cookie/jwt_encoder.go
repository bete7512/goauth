package cookie

import (
	"errors"
	"time"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/golang-jwt/jwt/v5"
)

var _ CookieEncoder = (*jwtEncoder)(nil)

// sessionClaims are the JWT claims for session cookies.
type sessionClaims struct {
	jwt.RegisteredClaims
	SessionID string `json:"sid"`
	UserID    string `json:"uid"`
}

// jwtEncoder uses standard HS256 JWT format.
// Larger than compact (~400 bytes) but interoperable with standard JWT tooling.
type jwtEncoder struct {
	signingKey []byte
}

func newJWTEncoder(key string) *jwtEncoder {
	return &jwtEncoder{signingKey: []byte(key)}
}

func (e *jwtEncoder) Encode(data *types.SessionCookieData) (string, error) {
	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(data.ExpiresAt, 0)),
			IssuedAt:  jwt.NewNumericDate(time.Unix(data.IssuedAt, 0)),
		},
		SessionID: data.SessionID,
		UserID:    data.UserID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(e.signingKey)
}

func (e *jwtEncoder) Decode(cookieValue string) (*types.SessionCookieData, error) {
	var claims sessionClaims
	token, err := jwt.ParseWithClaims(cookieValue, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidFormat
		}
		return e.signingKey, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpired
		}
		return nil, ErrInvalidHMAC
	}
	if !token.Valid {
		return nil, ErrInvalidHMAC
	}

	data := &types.SessionCookieData{
		SessionID: claims.SessionID,
		UserID:    claims.UserID,
	}
	if claims.ExpiresAt != nil {
		data.ExpiresAt = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		data.IssuedAt = claims.IssuedAt.Unix()
	}

	return data, nil
}

func (e *jwtEncoder) MaxSize() int {
	return 500
}

func (e *jwtEncoder) EncodingType() types.CookieEncoding {
	return types.CookieEncodingJWT
}
