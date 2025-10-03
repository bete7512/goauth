package core

import (
	"context"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/models"
	"gorm.io/gorm"
)

var _ models.SessionRepository = (*SessionRepository)(nil)

type SessionRepository struct {
	db *gorm.DB
}

func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(ctx context.Context, session *models.Session) error {
	return r.db.WithContext(ctx).Create(session).Error
}

func (r *SessionRepository) FindByToken(ctx context.Context, token string) (*models.Session, error) {
	var session *models.Session
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&session).Error
	return session, err
}

func (r *SessionRepository) FindByUserID(ctx context.Context, userID string) ([]*models.Session, error) {
	var sessions []*models.Session
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&sessions).Error
	return sessions, err
}

func (r *SessionRepository) Delete(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Where("token = ?", token).Delete(&models.Session{}).Error
}

func (r *SessionRepository) DeleteByUserID(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.Session{}).Error
}

func (r *SessionRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&models.Session{}).Error
}
