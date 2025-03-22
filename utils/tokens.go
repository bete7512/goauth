// auth/tokens.go
package utils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

// func GenerateTokens(userID string, duration time.Duration, secretKey string) (accessToken string, refreshToken string, err error) {
// 	// Generate access token
// 	accessToken, err = GenerateAccessToken(userID, duration, secretKey)
// 	if err != nil {
// 		return "", "", err
// 	}
// 	// Generate refresh token
// 	refreshToken, err = GenerateRefreshToken()
// 	if err != nil {
// 		return "", "", err
// 	}
// 	return accessToken, refreshToken, nil
// }

func GenerateAccessToken(userID string, duration time.Duration, secretKey string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(duration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func GenerateRefreshToken() (string, error) {
	// Implementation for refresh token generation
	return "", nil
}

// func ValidateToken(tokenString string, secretKey string) (jwt.MapClaims, error) {
// 	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 		return []byte(secretKey), nil
// 	})

// 	if err != nil {
// 		return nil, err
// 	}

// 	claims, ok := token.Claims.(jwt.MapClaims)
// 	if !ok || !token.Valid {
// 		return nil, err
// 	}

// 	return claims, nil
// }

// func HashPassword(password string) (string, error) {
// 	if len(password) < 8 {
// 		return "", errors.New("password must be at least 8 characters long")
// 	}

// 	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
// 	if err != nil {
// 		return "", errors.New("failed to hash password")
// 	}

// 	return string(hashedBytes), nil
// }

// func ValidatePassword(hashedPassword, password string) error {
// 	if len(hashedPassword) == 0 || len(password) == 0 {
// 		return errors.New("password and hash cannot be empty")
// 	}
// 	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
// 	if err != nil {
// 		if err == bcrypt.ErrMismatchedHashAndPassword {
// 			return errors.New("invalid password")
// 		}
// 		return errors.New("failed to validate password")
// 	}

// 	return nil
// }

// HashPassword creates a bcrypt hash of the password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// ValidatePassword checks if the provided password is correct
func ValidatePassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// GenerateTokens creates a new JWT access token and refresh token
func GenerateTokens(userID string, accessTokenttl time.Duration,refreshTokenTTl time.Duration, secret string) (accessToken string, refreshToken string, err error) {
	// Create access token
	accessTokenClaims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(accessTokenttl).Unix(),
		"iat":     time.Now().Unix(),
		"type":    "access",
	}
	accessTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessToken, err = accessTokenObj.SignedString([]byte(secret))
	if err != nil {
		return "", "", err
	}

	// Create refresh token
	refreshTokenClaims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(refreshTokenTTl).Unix(), // Refresh token lasts longer
		"iat":     time.Now().Unix(),
		"type":    "refresh",
	}
	refreshTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	refreshToken, err = refreshTokenObj.SignedString([]byte(secret))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// ValidateToken validates a JWT token
func ValidateToken(tokenString string, secret string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// GenerateRandomToken generates a random token with the specified length in bytes
func GenerateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateBase64Token generates a random base64 encoded token
func GenerateBase64Token(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
