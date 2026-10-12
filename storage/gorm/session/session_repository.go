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
	normalizeSessionTimes(session)
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
		Where("refresh_token = ? AND expires_at > ?", refreshToken, time.Now().UTC()).
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
		Where("user_id = ? AND expires_at > ?", userID, time.Now().UTC())

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
	normalizeSessionTimes(session)
	session.UpdatedAt = time.Now().UTC()
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
	result := r.db.WithContext(ctx).Where("expires_at < ?", time.Now().UTC()).Delete(&models.Session{})
	if result.Error != nil {
		return 0, fmt.Errorf("session_repository.DeleteExpired: %w", result.Error)
	}
	return result.RowsAffected, nil
}

// RotateToken atomically rotates the secret without extending the grant's age.
func (r *SessionRepository) RotateToken(ctx context.Context, oldToken string, newSession *models.Session) error {
	now := time.Now().UTC()
	result := r.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ? AND user_id = ? AND refresh_token = ? AND expires_at > ? AND refresh_token_expires_at > ?", newSession.ID, newSession.UserID, oldToken, now, now).
		Updates(map[string]interface{}{"refresh_token": newSession.RefreshToken, "refresh_token_expires_at": newSession.RefreshTokenExpiresAt.UTC(), "updated_at": now})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return models.ErrConflict
	}
	return nil
}

func normalizeSessionTimes(session *models.Session) {
	session.CreatedAt = session.CreatedAt.UTC()
	session.UpdatedAt = session.UpdatedAt.UTC()
	session.ExpiresAt = session.ExpiresAt.UTC()
	session.RefreshTokenExpiresAt = session.RefreshTokenExpiresAt.UTC()
}
