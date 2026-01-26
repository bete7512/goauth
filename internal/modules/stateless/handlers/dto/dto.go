package dto

import (
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/models"
)

// LoginRequest represents login request
type LoginRequest struct {
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
}

func (r *LoginRequest) Validate() error {
	if r.Email == "" && r.Username == "" {
		return fmt.Errorf("email or username is required")
	}
	if r.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}

// RefreshRequest represents token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (r *RefreshRequest) Validate() error {
	if r.RefreshToken == "" {
		return fmt.Errorf("refresh_token is required")
	}
	return nil
}

// AuthResponse represents authentication response
type AuthResponse struct {
	AccessToken  *string  `json:"access_token,omitempty"`
	RefreshToken *string  `json:"refresh_token,omitempty"`
	User         *UserDTO `json:"user"`
	ExpiresIn    int64    `json:"expires_in,omitempty"`
	Message      string   `json:"message,omitempty"`
}

// UserDTO represents user data in responses
type UserDTO struct {
	ID                  string               `json:"id"`
	FirstName           string               `json:"first_name,omitempty"`
	LastName            string               `json:"last_name,omitempty"`
	Name                string               `json:"name,omitempty"`
	Email               string               `json:"email"`
	Username            string               `json:"username,omitempty"`
	Avatar              string               `json:"avatar,omitempty"`
	PhoneNumber         string               `json:"phone_number,omitempty"`
	Active              bool                 `json:"active"`
	EmailVerified       bool                 `json:"email_verified"`
	PhoneNumberVerified bool                 `json:"phone_number_verified"`
	CreatedAt           time.Time            `json:"created_at"`
	UpdatedAt           *time.Time           `json:"updated_at"`
	LastLoginAt         *time.Time           `json:"last_login_at,omitempty"`
	ExtendedAttributes  []ExtendedAttributes `json:"extended_attributes,omitempty"`
}

type ExtendedAttributes struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func UserToDTO(user *models.User) *UserDTO {
	if user == nil {
		return nil
	}
	attrs := make([]ExtendedAttributes, len(user.ExtendedAttributes))
	for i, attr := range user.ExtendedAttributes {
		attrs[i] = ExtendedAttributes{Name: attr.Name, Value: attr.Value}
	}
	return &UserDTO{
		ID:                  user.ID,
		FirstName:           user.FirstName,
		LastName:            user.LastName,
		Name:                user.Name,
		Email:               user.Email,
		Username:            user.Username,
		Avatar:              user.Avatar,
		PhoneNumber:         user.PhoneNumber,
		Active:              user.Active,
		EmailVerified:       user.EmailVerified,
		PhoneNumberVerified: user.PhoneNumberVerified,
		CreatedAt:           user.CreatedAt,
		UpdatedAt:           user.UpdatedAt,
		LastLoginAt:         user.LastLoginAt,
		ExtendedAttributes:  attrs,
	}
}

func (u *UserDTO) ToUser() *models.User {
	if u == nil {
		return nil
	}
	attrs := make([]models.ExtendedAttributes, len(u.ExtendedAttributes))
	for i, attr := range u.ExtendedAttributes {
		attrs[i] = models.ExtendedAttributes{Name: attr.Name, Value: attr.Value}
	}
	return &models.User{
		ID:                  u.ID,
		FirstName:           u.FirstName,
		LastName:            u.LastName,
		Name:                u.Name,
		Email:               u.Email,
		Username:            u.Username,
		Avatar:              u.Avatar,
		PhoneNumber:         u.PhoneNumber,
		Active:              u.Active,
		EmailVerified:       u.EmailVerified,
		PhoneNumberVerified: u.PhoneNumberVerified,
		CreatedAt:           u.CreatedAt,
		UpdatedAt:           u.UpdatedAt,
		LastLoginAt:         u.LastLoginAt,
		ExtendedAttributes:  attrs,
	}
}

// MessageResponse represents a simple message response
type MessageResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}
