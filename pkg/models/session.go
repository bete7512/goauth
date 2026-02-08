package models

//go:generate mockgen -destination=../../internal/mocks/mock_session_repository.go -package=mocks github.com/bete7512/goauth/pkg/models SessionRepository

import (
	"context"
	"time"
)

type Session struct {
	ID                    string    `json:"id" gorm:"primaryKey"`
	UserID                string    `json:"user_id" gorm:"not null;index"`
	RefreshToken          string    `json:"refresh_token" gorm:"uniqueIndex;not null"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at" gorm:"not null;index"`
	ExpiresAt             time.Time `json:"expires_at" gorm:"not null;index"`
	UserAgent             string    `json:"user_agent"`
	IPAddress             string    `json:"ip_address"`
	ReplacedBy            string    `json:"replaced_by"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

func (Session) TableName() string {
	return "sessions"
}

type SessionRepository interface {
	Create(ctx context.Context, session *Session) error
	FindByID(ctx context.Context, id string) (*Session, error)
	FindByToken(ctx context.Context, token string) (*Session, error)
	FindByUserID(ctx context.Context, userID string, opts SessionListOpts) ([]*Session, int64, error)
	Update(ctx context.Context, session *Session) error
	Delete(ctx context.Context, id string) error
	DeleteByToken(ctx context.Context, token string) error
	DeleteByUserID(ctx context.Context, userID string) error
	DeleteExpired(ctx context.Context) (int64, error)
}
