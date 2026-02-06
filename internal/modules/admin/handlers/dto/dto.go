package dto

import (
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/models"
)

// AdminUserDTO represents user data in admin responses with additional privileged fields
type AdminUserDTO struct {
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
	IsSuperAdmin        bool                 `json:"is_super_admin"`
	TokenVersion        int                  `json:"token_version"`
	CreatedAt           time.Time            `json:"created_at"`
	UpdatedAt           *time.Time           `json:"updated_at"`
	LastLoginAt         *time.Time           `json:"last_login_at,omitempty"`
	ExtendedAttributes  []ExtendedAttributes `json:"extended_attributes,omitempty"`
}

type ExtendedAttributes struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// UpdateUserRequest represents admin user update request
type UpdateUserRequest struct {
	FirstName           *string `json:"first_name,omitempty"`
	LastName            *string `json:"last_name,omitempty"`
	Name                *string `json:"name,omitempty"`
	Email               *string `json:"email,omitempty"`
	Username            *string `json:"username,omitempty"`
	Avatar              *string `json:"avatar,omitempty"`
	PhoneNumber         *string `json:"phone_number,omitempty"`
	Active              *bool   `json:"active,omitempty"`
	EmailVerified       *bool   `json:"email_verified,omitempty"`
	PhoneNumberVerified *bool   `json:"phone_number_verified,omitempty"`
	IsSuperAdmin        *bool   `json:"is_super_admin,omitempty"`
}

func (r *UpdateUserRequest) Validate() error {
	// At least one field must be provided
	if r.FirstName == nil && r.LastName == nil && r.Name == nil &&
		r.Email == nil && r.Username == nil && r.Avatar == nil &&
		r.PhoneNumber == nil && r.Active == nil && r.EmailVerified == nil &&
		r.PhoneNumberVerified == nil && r.IsSuperAdmin == nil {
		return fmt.Errorf("at least one field must be provided for update")
	}
	return nil
}

// ApplyTo applies the update request to a user model
func (r *UpdateUserRequest) ApplyTo(user *models.User) {
	if r.FirstName != nil {
		user.FirstName = *r.FirstName
	}
	if r.LastName != nil {
		user.LastName = *r.LastName
	}
	if r.Name != nil {
		user.Name = *r.Name
	}
	if r.Email != nil {
		user.Email = *r.Email
	}
	if r.Username != nil {
		user.Username = *r.Username
	}
	if r.Avatar != nil {
		user.Avatar = *r.Avatar
	}
	if r.PhoneNumber != nil {
		user.PhoneNumber = *r.PhoneNumber
	}
	if r.Active != nil {
		user.Active = *r.Active
	}
	if r.EmailVerified != nil {
		user.EmailVerified = *r.EmailVerified
	}
	if r.PhoneNumberVerified != nil {
		user.PhoneNumberVerified = *r.PhoneNumberVerified
	}
	if r.IsSuperAdmin != nil {
		user.IsSuperAdmin = *r.IsSuperAdmin
	}
}

// UserToAdminDTO converts a user model to admin DTO
func UserToAdminDTO(user *models.User) *AdminUserDTO {
	if user == nil {
		return nil
	}
	attrs := make([]ExtendedAttributes, len(user.ExtendedAttributes))
	for i, attr := range user.ExtendedAttributes {
		attrs[i] = ExtendedAttributes{
			ID:    attr.ID,
			Name:  attr.Name,
			Value: attr.Value,
		}
	}
	return &AdminUserDTO{
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
		IsSuperAdmin:        user.IsSuperAdmin,
		TokenVersion:        user.TokenVersion,
		CreatedAt:           user.CreatedAt,
		UpdatedAt:           user.UpdatedAt,
		LastLoginAt:         user.LastLoginAt,
		ExtendedAttributes:  attrs,
	}
}

// UsersToAdminDTO converts multiple users to admin DTOs
func UsersToAdminDTO(users []*models.User) []*AdminUserDTO {
	if users == nil {
		return nil
	}
	dtos := make([]*AdminUserDTO, len(users))
	for i, user := range users {
		dtos[i] = UserToAdminDTO(user)
	}
	return dtos
}

// MessageResponse represents a simple message response
type MessageResponse struct {
	Message string `json:"message"`
}
