package postgres

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type SessionRepository struct {
	Db *gorm.DB
}

func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{Db: db}
}

func (r *SessionRepository) GetSessionByUserID(ctx context.Context, userID string) ([]models.Session, error) {
	var sessions []models.Session
	if err := r.Db.WithContext(ctx).Where("user_id = ?", userID).Find(&sessions).Error; err != nil {
		return nil, err
	}
	return sessions, nil
}

func (r *SessionRepository) GetSessionBySessionID(ctx context.Context, sessionID string) (*models.Session, error) {
	var session models.Session
	if err := r.Db.WithContext(ctx).Where("id = ?", sessionID).First(&session).Error; err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *SessionRepository) CreateSession(ctx context.Context, session *models.Session) error {
	return r.Db.WithContext(ctx).Create(session).Error
}

func (r *SessionRepository) UpdateSession(ctx context.Context, session *models.Session) error {
	return r.Db.WithContext(ctx).Save(session).Error
}

func (r *SessionRepository) DeleteSession(ctx context.Context, session *models.Session) error {
	return r.Db.WithContext(ctx).Delete(session).Error
}

func (r *SessionRepository) DeleteAllUserSessions(ctx context.Context, userID string) error {
	return r.Db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.Session{}).Error
}
