// auth/tokens.go
package utils

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func  GenerateTokens(userID string, duration time.Duration,secretKey string) (accessToken string, refreshToken string, err error) {
	// Generate access token
	accessToken, err = GenerateAccessToken(userID,duration,secretKey)
	if err != nil {
		return "", "", err
	}

	// Generate refresh token
	refreshToken, err = GenerateRefreshToken()
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func  GenerateAccessToken(userID string, duration time.Duration,secretKey string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(duration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func  GenerateRefreshToken() (string, error) {
	// Implementation for refresh token generation
	return "", nil
}

func  ValidateToken(tokenString string,secretKey string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}

	return claims, nil
}

func  HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters long")
	}

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.New("failed to hash password")
	}

	return string(hashedBytes), nil
}

func  ValidatePassword(hashedPassword, password string) error {
	if len(hashedPassword) == 0 || len(password) == 0 {
		return errors.New("password and hash cannot be empty")
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return errors.New("invalid password")
		}
		return errors.New("failed to validate password")
	}

	return nil
}
