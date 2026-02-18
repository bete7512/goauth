package oauth

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

// AccountRepository implements models.AccountRepository using GORM
type AccountRepository struct {
	db *gorm.DB
}

// NewAccountRepository creates a new account repository
func NewAccountRepository(db *gorm.DB) *AccountRepository {
	return &AccountRepository{db: db}
}

// Create creates a new account
func (r *AccountRepository) Create(ctx context.Context, account *models.Account) error {
	return r.db.WithContext(ctx).Create(account).Error
}

// FindByID finds an account by its ID
func (r *AccountRepository) FindByID(ctx context.Context, id string) (*models.Account, error) {
	var account models.Account
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&account).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &account, nil
}

// FindByProviderAndAccountID finds an account by provider and provider's user ID
func (r *AccountRepository) FindByProviderAndAccountID(ctx context.Context, provider, providerAccountID string) (*models.Account, error) {
	var account models.Account
	err := r.db.WithContext(ctx).
		Where("provider = ? AND provider_account_id = ?", provider, providerAccountID).
		First(&account).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &account, nil
}

// FindByUserID finds all accounts for a user
func (r *AccountRepository) FindByUserID(ctx context.Context, userID string) ([]*models.Account, error) {
	var accounts []*models.Account
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&accounts).Error
	if err != nil {
		return nil, err
	}
	return accounts, nil
}

// FindByUserIDAndProvider finds a specific provider account for a user
func (r *AccountRepository) FindByUserIDAndProvider(ctx context.Context, userID, provider string) (*models.Account, error) {
	var account models.Account
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND provider = ?", userID, provider).
		First(&account).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &account, nil
}

// Update updates an account
func (r *AccountRepository) Update(ctx context.Context, account *models.Account) error {
	return r.db.WithContext(ctx).Save(account).Error
}

// Delete deletes an account by ID
func (r *AccountRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&models.Account{}, "id = ?", id).Error
}

// DeleteByUserIDAndProvider deletes a user's account for a specific provider
func (r *AccountRepository) DeleteByUserIDAndProvider(ctx context.Context, userID, provider string) error {
	return r.db.WithContext(ctx).
		Delete(&models.Account{}, "user_id = ? AND provider = ?", userID, provider).Error
}

// CountByUserID counts the number of accounts for a user
func (r *AccountRepository) CountByUserID(ctx context.Context, userID string) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&models.Account{}).
		Where("user_id = ?", userID).
		Count(&count).Error
	return count, err
}
