package core

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ExtendedAttributeRepository struct {
	db *gorm.DB
}

func (r *ExtendedAttributeRepository) Create(ctx context.Context, attr *models.ExtendedAttributes) error {
	if attr.ID == "" {
		attr.ID = uuid.New().String()
	}
	if attr.CreatedAt.IsZero() {
		attr.CreatedAt = time.Now()
	}
	attr.UpdatedAt = time.Now()
	return r.db.WithContext(ctx).Create(attr).Error
}

func (r *ExtendedAttributeRepository) FindByUserAndName(ctx context.Context, userID string, name string) (*models.ExtendedAttributes, error) {
	var attr models.ExtendedAttributes
	err := r.db.WithContext(ctx).Where("user_id = ? AND name = ?", userID, name).First(&attr).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &attr, err
}

func (r *ExtendedAttributeRepository) FindByNameAndValue(ctx context.Context, name string, value string) (*models.ExtendedAttributes, error) {
	var attr models.ExtendedAttributes
	err := r.db.WithContext(ctx).Where("name = ? AND value = ?", name, value).First(&attr).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &attr, err
}

func (r *ExtendedAttributeRepository) Upsert(ctx context.Context, userID string, name string, value string) error {
	var existing models.ExtendedAttributes
	res := r.db.WithContext(ctx).Where("user_id = ? AND name = ?", userID, name).First(&existing)
	if res.Error == nil {
		existing.Value = value
		existing.UpdatedAt = time.Now()
		return r.db.WithContext(ctx).Save(&existing).Error
	}
	if res.Error != gorm.ErrRecordNotFound {
		return res.Error
	}
	attr := &models.ExtendedAttributes{
		ID:        uuid.New().String(),
		UserId:    userID,
		Name:      name,
		Value:     value,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return r.db.WithContext(ctx).Create(attr).Error
}

func (r *ExtendedAttributeRepository) UpsertMany(ctx context.Context, attrs []models.ExtendedAttributes) error {
	for i := range attrs {
		if attrs[i].ID == "" {
			attrs[i].ID = uuid.New().String()
		}
		if attrs[i].CreatedAt.IsZero() {
			attrs[i].CreatedAt = time.Now()
		}
		attrs[i].UpdatedAt = time.Now()
	}
	return r.db.WithContext(ctx).Save(&attrs).Error
}

func (r *ExtendedAttributeRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&models.ExtendedAttributes{}, "id = ?", id).Error
}
