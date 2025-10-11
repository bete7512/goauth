package core

import (
	"context"

	"github.com/bete7512/goauth/internal/modules/core/models"
	"gorm.io/gorm"
)

type UserExtendedAttributeRepository struct {
	db *gorm.DB
}

var _ models.ExtendedAttributesRepository = (*UserExtendedAttributeRepository)(nil)

func NewUserExtendedAttributeRepository(db *gorm.DB) *UserExtendedAttributeRepository {
	return &UserExtendedAttributeRepository{db: db}
}

func (r *UserExtendedAttributeRepository) Create(ctx context.Context, attr *models.ExtendedAttributes) error {
	return r.db.WithContext(ctx).Create(attr).Error
}

func (r *UserExtendedAttributeRepository) FindByUserAndName(ctx context.Context, userID string, name string) (*models.ExtendedAttributes, error) {
	var attr *models.ExtendedAttributes
	err := r.db.WithContext(ctx).Where("user_id = ? AND name = ?", userID, name).First(&attr).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return attr, err
}

func (r *UserExtendedAttributeRepository) FindByNameAndValue(ctx context.Context, name string, value string) (*models.ExtendedAttributes, error) {
	var attr *models.ExtendedAttributes
	err := r.db.WithContext(ctx).Where("name = ? AND value = ?", name, value).First(&attr).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return attr, err
}

func (r *UserExtendedAttributeRepository) Upsert(ctx context.Context, userID string, name string, value string) error {
	// Try to update existing
	var existing models.ExtendedAttributes
	res := r.db.WithContext(ctx).Where("user_id = ? AND name = ?", userID, name).First(&existing)
	if res.Error == nil {
		existing.Value = value
		return r.db.WithContext(ctx).Save(&existing).Error
	}
	if res.Error != gorm.ErrRecordNotFound {
		return res.Error
	}
	// Create new
	attr := &models.ExtendedAttributes{UserId: userID, Name: name, Value: value}
	return r.db.WithContext(ctx).Create(attr).Error
}

func (r *UserExtendedAttributeRepository) UpsertMany(ctx context.Context, attrs []models.ExtendedAttributes) error {
	return r.db.WithContext(ctx).Create(&attrs).Error
}

func (r *UserExtendedAttributeRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&models.ExtendedAttributes{}, id).Error
}
