package session

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/storage/gorm/helpers"
	"gorm.io/gorm"
)

type SessionRepository struct {
	db *gorm.DB
}

func (r *SessionRepository) Create(ctx context.Context, session *models.Session) error {
	if err := r.db.WithContext(ctx).Create(session).Error; err != nil {
		return fmt.Errorf("session_repository.Create: %w", err)
	}
	return nil
}

func (r *SessionRepository) FindByID(ctx context.Context, id string) (*models.Session, error) {
	var session models.Session
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&session).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("session_repository.FindByID: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("session_repository.FindByID: %w", err)
	}
	return &session, nil
}

func (r *SessionRepository) FindByToken(ctx context.Context, refreshToken string) (*models.Session, error) {
	var session models.Session
	err := r.db.WithContext(ctx).
		Where("refresh_token = ? AND expires_at > ?", refreshToken, time.Now()).
		First(&session).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("session_repository.FindByToken: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("session_repository.FindByToken: %w", err)
	}
	return &session, nil
}

func (r *SessionRepository) FindByUserID(ctx context.Context, userID string, opts models.SessionListOpts) ([]*models.Session, int64, error) {
	var total int64
	baseQuery := r.db.WithContext(ctx).Model(&models.Session{}).
		Where("user_id = ? AND expires_at > ?", userID, time.Now())

	if err := baseQuery.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("session_repository.FindByUserID count: %w", err)
	}

	var sessions []*models.Session
	if err := helpers.ApplyListingOpts(baseQuery, opts.ListingOpts).Find(&sessions).Error; err != nil {
		return nil, 0, fmt.Errorf("session_repository.FindByUserID find: %w", err)
	}
	return sessions, total, nil
}

func (r *SessionRepository) Update(ctx context.Context, session *models.Session) error {
	session.UpdatedAt = time.Now()
	if err := r.db.WithContext(ctx).Save(session).Error; err != nil {
		return fmt.Errorf("session_repository.Update: %w", err)
	}
	return nil
}

func (r *SessionRepository) Delete(ctx context.Context, id string) error {
	if err := r.db.WithContext(ctx).Where("id = ?", id).Delete(&models.Session{}).Error; err != nil {
		return fmt.Errorf("session_repository.Delete: %w", err)
	}
	return nil
}

func (r *SessionRepository) DeleteByToken(ctx context.Context, refreshToken string) error {
	if err := r.db.WithContext(ctx).Where("refresh_token = ?", refreshToken).Delete(&models.Session{}).Error; err != nil {
		return fmt.Errorf("session_repository.DeleteByToken: %w", err)
	}
	return nil
}

func (r *SessionRepository) DeleteByUserID(ctx context.Context, userID string) error {
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.Session{}).Error; err != nil {
		return fmt.Errorf("session_repository.DeleteByUserID: %w", err)
	}
	return nil
}

func (r *SessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&models.Session{})
	if result.Error != nil {
		return 0, fmt.Errorf("session_repository.DeleteExpired: %w", result.Error)
	}
	return result.RowsAffected, nil
}

// RotateToken atomically replaces an old session with a new one
// Prevents race conditions during token refresh
func (r *SessionRepository) RotateToken(ctx context.Context, oldToken string, newSession *models.Session) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("refresh_token = ?", oldToken).Delete(&models.Session{}).Error; err != nil {
			return fmt.Errorf("session_repository.RotateToken delete: %w", err)
		}
		if err := tx.Create(newSession).Error; err != nil {
			return fmt.Errorf("session_repository.RotateToken create: %w", err)
		}
		return nil
	})
}
