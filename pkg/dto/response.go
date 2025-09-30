package dto

import (
	"time"

	"github.com/bete7512/goauth/pkg/models"
)

// Login response
type LoginResponse struct {
	User         *UserResponse `json:"user"`
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	ExpiresIn    int64         `json:"expires_in"`
	TokenType    string        `json:"token_type"`
}

// User response (sanitized user data)
type UserResponse struct {
	ID               string     `json:"id"`
	FirstName        string     `json:"first_name"`
	LastName         string     `json:"last_name"`
	Email            string     `json:"email"`
	EmailVerified    bool       `json:"email_verified"`
	PhoneNumber      *string    `json:"phone_number,omitempty"`
	PhoneVerified    bool       `json:"phone_verified"`
	TwoFactorEnabled bool       `json:"two_factor_enabled"`
	Avatar           *string    `json:"avatar,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
}

// Convert model to response
func (u *UserResponse) FromModel(user *models.User) {
	u.ID = user.ID
	u.FirstName = user.FirstName
	u.LastName = user.LastName
	u.Email = user.Email
	u.EmailVerified = user.EmailVerified != nil && *user.EmailVerified
	u.PhoneNumber = user.PhoneNumber
	u.PhoneVerified = user.PhoneVerified != nil && *user.PhoneVerified
	u.TwoFactorEnabled = user.TwoFactorEnabled != nil && *user.TwoFactorEnabled
	u.Avatar = user.Avatar
	u.CreatedAt = user.CreatedAt
	u.UpdatedAt = user.UpdatedAt
	u.LastLoginAt = user.LastLoginAt
}

// List users response
type ListUsersResponse struct {
	Users      []UserResponse `json:"users"`
	Pagination PaginationMeta `json:"pagination"`
}

// Error response
type ErrorResponse struct {
	Error *GoAuthError `json:"error"`
}
