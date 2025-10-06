package core

import (
	"context"

	"github.com/bete7512/goauth/internal/modules/core/models"
	"gorm.io/gorm"
)

type UserRepository struct {
	db *gorm.DB
}

var _ models.UserRepository = (*UserRepository)(nil)

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	var user *models.User
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	// if user is not found, return nil
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return user, err
}
func (r *UserRepository) FindByID(ctx context.Context, id string) (*models.User, error) {
	var user *models.User
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	// if user is not found, return nil
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return user, err
}

func (r *UserRepository) List(ctx context.Context, limit, offset int) ([]*models.User, error) {
	var users []*models.User
	err := r.db.WithContext(ctx).Limit(limit).Offset(offset).Find(&users).Error
	return users, err
}
func (r *UserRepository) Update(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}
func (r *UserRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&models.User{}, id).Error
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	var user *models.User
	err := r.db.WithContext(ctx).Where("username = ?", username).First(&user).Error
	// if user is not found, return nil
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return user, err
}

func (r *UserRepository) FindByPhone(ctx context.Context, phone string) (*models.User, error) {
	var user *models.User
	err := r.db.WithContext(ctx).Where("phone = ?", phone).First(&user).Error
	// if user is not found, return nil
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return user, err
}

func (r *UserRepository) FindByEmailOrUsername(ctx context.Context, emailOrUsername string) (*models.User, error) {
	var user *models.User
	err := r.db.WithContext(ctx).Where("email = ? OR username = ?", emailOrUsername, emailOrUsername).First(&user).Error
	// if user is not found, return nil
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return user, err
}

func (r *UserRepository) CheckAvailability(ctx context.Context, field, value string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.User{}).Where(field+" = ?", value).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count == 0, nil
}
