package core

import (
	"context"
	"fmt"

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

func (r *UserRepository) IsAvailable(ctx context.Context, field, value string) (bool, error) {
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
