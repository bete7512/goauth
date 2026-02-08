package models

//go:generate mockgen -destination=../../internal/mocks/mock_user_repository.go -package=mocks github.com/bete7512/goauth/pkg/models UserRepository,ExtendedAttributeRepository

import (
	"context"
	"time"
)

type User struct {
	ID                  string               `json:"id" gorm:"primaryKey"`
	Name                string               `json:"name"`
	FirstName           string               `json:"first_name"`
	LastName            string               `json:"last_name"`
	Email               string               `json:"email" gorm:"uniqueIndex;not null"`
	Username            string               `json:"username" gorm:"uniqueIndex"`
	PasswordHash        string               `json:"-" gorm:"column:password;not null"`
	Avatar              string               `json:"avatar"`
	PhoneNumber         string               `json:"phone_number"`
	Active              bool                 `json:"active" gorm:"default:true"`
	EmailVerified       bool                 `json:"email_verified" gorm:"default:false"`
	PhoneNumberVerified bool                 `json:"phone_number_verified" gorm:"default:false"`
	IsSuperAdmin        bool                 `json:"is_super_admin" gorm:"default:false;not null;index"`
	// TokenVersion is used for stateless token revocation
	// Incrementing this value invalidates all existing tokens for the user
	TokenVersion       int                  `json:"-" gorm:"default:0;not null"`
	CreatedAt          time.Time            `json:"created_at"`
	LastLoginAt        *time.Time           `json:"last_login_at"`
	UpdatedAt          *time.Time           `json:"updated_at"`
	ExtendedAttributes []ExtendedAttributes `json:"extended_attributes" gorm:"foreignKey:UserId;references:ID"`
}

type ExtendedAttributes struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	UserId    string    `json:"user_id" gorm:"not null;index"`
	Name      string    `json:"name" gorm:"not null"`
	Value     string    `json:"value" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type UserRepository interface {
	Create(ctx context.Context, user *User) error
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByUsername(ctx context.Context, username string) (*User, error)
	FindByPhoneNumber(ctx context.Context, phoneNumber string) (*User, error)
	FindByEmailOrUsername(ctx context.Context, emailOrUsername string) (*User, error)
	List(ctx context.Context, opts UserListOpts) ([]*User, int64, error)
	FindByID(ctx context.Context, id string) (*User, error)
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id string) error
	IsAvailable(ctx context.Context, field, value string) (bool, error)
}

type ExtendedAttributeRepository interface {
	Create(ctx context.Context, attr *ExtendedAttributes) error
	FindByUserAndName(ctx context.Context, userID string, name string) (*ExtendedAttributes, error)
	FindByNameAndValue(ctx context.Context, name string, value string) (*ExtendedAttributes, error)
	Upsert(ctx context.Context, userID string, name string, value string) error
	UpsertMany(ctx context.Context, attrs []ExtendedAttributes) error
	Delete(ctx context.Context, id string) error
}

func (ExtendedAttributes) TableName() string {
	return "extended_attributes"
}

func (User) TableName() string {
	return "users"
}
