package core

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/storage/gorm/helpers"
	"gorm.io/gorm"
)

type UserRepository struct {
	db *gorm.DB
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return fmt.Errorf("user_repository.Create: %w", err)
	}
	return nil
}

func (r *UserRepository) FindByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("user_repository.FindByID: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("user_repository.FindByID: %w", err)
	}
	return &user, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("user_repository.FindByEmail: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("user_repository.FindByEmail: %w", err)
	}
	return &user, nil
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("username = ?", username).First(&user).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("user_repository.FindByUsername: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("user_repository.FindByUsername: %w", err)
	}
	return &user, nil
}

func (r *UserRepository) FindByPhoneNumber(ctx context.Context, phoneNumber string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("phone_number = ?", phoneNumber).First(&user).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("user_repository.FindByPhoneNumber: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("user_repository.FindByPhoneNumber: %w", err)
	}
	return &user, nil
}

func (r *UserRepository) FindByEmailOrUsername(ctx context.Context, emailOrUsername string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("email = ? OR username = ?", emailOrUsername, emailOrUsername).First(&user).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("user_repository.FindByEmailOrUsername: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("user_repository.FindByEmailOrUsername: %w", err)
	}
	return &user, nil
}

func (r *UserRepository) List(ctx context.Context, opts models.UserListOpts) ([]*models.User, int64, error) {
	query := r.db.WithContext(ctx).Model(&models.User{})

	if opts.Query != "" {
		search := "%" + opts.Query + "%"
		query = query.Where("name ILIKE ? OR email ILIKE ? OR username ILIKE ?", search, search, search)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("user_repository.List count: %w", err)
	}

	var users []*models.User
	if err := helpers.ApplyListingOpts(query, opts.ListingOpts).Find(&users).Error; err != nil {
		return nil, 0, fmt.Errorf("user_repository.List find: %w", err)
	}
	return users, total, nil
}

func (r *UserRepository) Update(ctx context.Context, user *models.User) error {
	if err := r.db.WithContext(ctx).Save(user).Error; err != nil {
		return fmt.Errorf("user_repository.Update: %w", err)
	}
	return nil
}

func (r *UserRepository) Delete(ctx context.Context, id string) error {
	if err := r.db.WithContext(ctx).Delete(&models.User{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("user_repository.Delete: %w", err)
	}
	return nil
}

// allowedAvailabilityFields whitelists column names to prevent SQL injection.
var allowedAvailabilityFields = []string{"email", "username", "phone_number"}

func (r *UserRepository) IsAvailable(ctx context.Context, field, value string) (bool, error) {
	if !slices.Contains(allowedAvailabilityFields, field) {
		return false, fmt.Errorf("user_repository.IsAvailable: invalid field %q", field)
	}
	var count int64
	err := r.db.WithContext(ctx).Model(&models.User{}).Where(field+" = ?", value).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("user_repository.IsAvailable: %w", err)
	}
	return count > 0, nil
}

func (r *UserRepository) IncrementTokenVersion(ctx context.Context, userID string) error {
	if err := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		UpdateColumn("token_version", gorm.Expr("token_version + 1")).
		Error; err != nil {
		return fmt.Errorf("user_repository.IncrementTokenVersion: %w", err)
	}
	return nil
}

func (r *UserRepository) RevokeTokens(ctx context.Context, id string) error {
	result := r.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", id).UpdateColumn("token_version", gorm.Expr("token_version + 1"))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return models.ErrNotFound
	}
	return nil
}

func (r *UserRepository) ChangePassword(ctx context.Context, id, previous, next string) error {
	result := r.db.WithContext(ctx).Model(&models.User{}).Where("id = ? AND password = ?", id, previous).Updates(map[string]interface{}{"password": next, "token_version": gorm.Expr("token_version + 1"), "updated_at": time.Now().UTC(), "failed_login_attempts": 0, "locked_until": nil})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return models.ErrConflict
	}
	return nil
}

func (r *UserRepository) RecordLogin(ctx context.Context, id string, version int, at time.Time) error {
	result := r.db.WithContext(ctx).Model(&models.User{}).Where("id = ? AND token_version = ?", id, version).Updates(map[string]interface{}{"last_login_at": at.UTC(), "failed_login_attempts": 0, "locked_until": nil})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return models.ErrConflict
	}
	return nil
}

func (r *UserRepository) RecordFailedLogin(ctx context.Context, id string, version, threshold int, duration time.Duration) (*models.User, error) {
	now := time.Now().UTC()
	// All expressions use the persisted counter. Expired locks start a new window.
	count := "CASE WHEN locked_until IS NOT NULL AND locked_until <= ? THEN 1 ELSE failed_login_attempts + 1 END"
	var user *models.User
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&models.User{}).
			Where("id = ? AND token_version = ? AND (locked_until IS NULL OR locked_until <= ?)", id, version, now).
			Updates(map[string]interface{}{
				"failed_login_attempts": gorm.Expr(count, now),
				"locked_until":          gorm.Expr("CASE WHEN locked_until <= ? THEN NULL ELSE locked_until END", now),
			})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return models.ErrConflict
		}
		if err := tx.Model(&models.User{}).Where("id = ? AND failed_login_attempts >= ?", id, threshold).
			UpdateColumn("locked_until", now.Add(duration)).Error; err != nil {
			return err
		}
		var err error
		user, err = (&UserRepository{db: tx}).FindByID(ctx, id)
		return err
	})
	return user, err
}

func (r *UserRepository) VerifyContact(ctx context.Context, id, contact string, email bool) error {
	column, verified := "phone_number", "phone_number_verified"
	if email {
		column, verified = "email", "email_verified"
	}
	result := r.db.WithContext(ctx).Model(&models.User{}).Where("id = ? AND "+column+" = ?", id, contact).
		Updates(map[string]interface{}{verified: true, "updated_at": time.Now().UTC()})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return models.ErrConflict
	}
	return nil
}

func (r *UserRepository) UpdateProfile(ctx context.Context, id, name, phone, avatar string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if phone != "" {
			if err := tx.Model(&models.User{}).Where("id = ? AND (phone_number IS NULL OR phone_number <> ?)", id, phone).
				Updates(map[string]interface{}{"phone_number": phone, "phone_number_verified": false, "token_version": gorm.Expr("token_version + 1")}).Error; err != nil {
				return err
			}
		}
		updates := map[string]interface{}{"updated_at": time.Now().UTC()}
		if name != "" {
			updates["name"] = name
		}
		if avatar != "" {
			updates["avatar"] = avatar
		}
		result := tx.Model(&models.User{}).Where("id = ?", id).Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return models.ErrNotFound
		}
		return nil
	})
}
