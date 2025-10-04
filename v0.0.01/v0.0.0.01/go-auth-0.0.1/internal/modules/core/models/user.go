package models

import (
	"context"
	"time"
)

type User struct {
	ID            string     `json:"id" gorm:"primaryKey"`
	Email         string     `json:"email" gorm:"uniqueIndex;not null"`
	Username      string     `json:"username" gorm:"uniqueIndex"`
	PasswordHash  string     `json:"-" gorm:"column:password;not null"`
	Name          string     `json:"name"`
	Avatar        string     `json:"avatar"`
	Phone         string     `json:"phone" gorm:"index"`
	Active        bool       `json:"active" gorm:"default:true"`
	EmailVerified bool       `json:"email_verified" gorm:"default:false"`
	PhoneVerified bool       `json:"phone_verified" gorm:"default:false"`
	LastLoginAt   *time.Time `json:"last_login_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type UserRepository interface {
	Create(ctx context.Context, user *User) error
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByUsername(ctx context.Context, username string) (*User, error)
	FindByPhone(ctx context.Context, phone string) (*User, error)
	FindByEmailOrUsername(ctx context.Context, emailOrUsername string) (*User, error)
	List(ctx context.Context, limit, offset int) ([]*User, error)
	FindByID(ctx context.Context, id string) (*User, error)
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id string) error
	CheckAvailability(ctx context.Context, field, value string) (bool, error)
}

func (User) TableName() string {
	return "users"
}
