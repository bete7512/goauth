package models

//go:generate mockgen -destination=../../internal/mocks/mock_session_repository.go -package=mocks github.com/bete7512/goauth/pkg/models SessionRepository,RotatingSessionRepository

import (
	"context"
	"time"
)

// Session is a server-side login session. RefreshToken holds the SHA-256
// digest of the refresh secret, never the secret itself.
type Session struct {
	AuthData              string    `json:"-" gorm:"type:text"`
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

// SessionRotator changes the refresh secret of the same logical session using
// a conditional write. It preserves ID, user, creation time and absolute expiry.
type SessionRotator interface {
	RotateToken(ctx context.Context, oldToken string, session *Session) error
}

// RotatingSessionRepository is a SessionRepository that rotates refresh
// secrets atomically.
type RotatingSessionRepository interface {
	SessionRepository
	SessionRotator
}

// TableName returns the database table name.
func (Session) TableName() string {
	return "sessions"
}

// SessionRepository persists sessions.
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
