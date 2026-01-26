package session

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type SessionRepository struct {
	db *gorm.DB
}

func (r *SessionRepository) Create(ctx context.Context, session *models.Session) error {
	return r.db.WithContext(ctx).Create(session).Error
}

func (r *SessionRepository) FindByID(ctx context.Context, id string) (*models.Session, error) {
	var session models.Session
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&session).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &session, err
}

func (r *SessionRepository) FindByToken(ctx context.Context, refreshToken string) (*models.Session, error) {
	var session models.Session
	err := r.db.WithContext(ctx).
		Where("refresh_token = ? AND expires_at > ?", refreshToken, time.Now()).
		First(&session).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &session, err
}

func (r *SessionRepository) FindByUserID(ctx context.Context, userID string) ([]*models.Session, error) {
	var sessions []*models.Session
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND expires_at > ?", userID, time.Now()).
		Order("created_at DESC").
		Find(&sessions).Error
	return sessions, err
}

func (r *SessionRepository) Update(ctx context.Context, session *models.Session) error {
	session.UpdatedAt = time.Now()
	return r.db.WithContext(ctx).Save(session).Error
}

func (r *SessionRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Where("id = ?", id).Delete(&models.Session{}).Error
}

func (r *SessionRepository) DeleteByToken(ctx context.Context, refreshToken string) error {
	return r.db.WithContext(ctx).Where("refresh_token = ?", refreshToken).Delete(&models.Session{}).Error
}

func (r *SessionRepository) DeleteByUserID(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.Session{}).Error
}

func (r *SessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&models.Session{})
	return result.RowsAffected, result.Error
}

// RotateToken atomically replaces an old session with a new one
// Prevents race conditions during token refresh
func (r *SessionRepository) RotateToken(ctx context.Context, oldToken string, newSession *models.Session) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Delete old session
		if err := tx.Where("refresh_token = ?", oldToken).Delete(&models.Session{}).Error; err != nil {
			return err
		}
		// Create new session
		return tx.Create(newSession).Error
	})
}
