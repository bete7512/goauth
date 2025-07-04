package mysql

import (
	"context"

	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type SessionRepository struct {
	db *gorm.DB
}

func NewSessionRepository(db *gorm.DB) interfaces.SessionRepository {
	return &SessionRepository{db: db}
}

func (s *SessionRepository) GetSessionByUserID(ctx context.Context, userID string) ([]models.Session, error) {
	var sessions []models.Session
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Find(&sessions).Error; err != nil {
		return nil, err
	}
	return sessions, nil
}

func (s *SessionRepository) GetSessionBySessionID(ctx context.Context, sessionID string) (*models.Session, error) {
	var session models.Session
	if err := s.db.WithContext(ctx).Where("id = ?", sessionID).First(&session).Error; err != nil {
		return nil, err
	}
	return &session, nil
}

func (s *SessionRepository) CreateSession(ctx context.Context, session *models.Session) error {
	return s.db.WithContext(ctx).Create(session).Error
}

func (s *SessionRepository) UpdateSession(ctx context.Context, session *models.Session) error {
	return s.db.WithContext(ctx).Save(session).Error
}

func (s *SessionRepository) DeleteSession(ctx context.Context, session *models.Session) error {
	return s.db.WithContext(ctx).Delete(session).Error
}

func (s *SessionRepository) DeleteAllUserSessions(ctx context.Context, userID string) error {
	return s.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.Session{}).Error
}
