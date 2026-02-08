package models

//go:generate mockgen -destination=../../internal/mocks/mock_token_repository.go -package=mocks github.com/bete7512/goauth/pkg/models TokenRepository

import (
	"context"
	"time"
)

type Token struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	UserID    string    `json:"user_id" gorm:"not null;index"`
	Type      string    `json:"type" gorm:"not null;index"`
	Token     string    `json:"token" gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null;index"`
	Used      bool      `json:"used" gorm:"default:false"`
	CreatedAt time.Time `json:"created_at"`
}

type TokenRepository interface {
	Create(ctx context.Context, token *Token) error
	FindByToken(ctx context.Context, token string) (*Token, error)
	FindByUserID(ctx context.Context, userID string) ([]*Token, error)
	Delete(ctx context.Context, token string) error
	DeleteByUserID(ctx context.Context, userID string) error
	DeleteExpired(ctx context.Context) (int64, error)
}

func (Token) TableName() string {
	return "tokens"
}
