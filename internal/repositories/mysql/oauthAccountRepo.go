package mysql

import (
	"context"
	"errors"
	"fmt"

	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type OauthAccountRepository struct {
	db *gorm.DB
}

func NewOauthAccountRepository(db *gorm.DB) interfaces.OauthAccountRepository {
	return &OauthAccountRepository{db: db}
}

func (o *OauthAccountRepository) GetOauthAccountByUserID(ctx context.Context, userID string) (*models.OauthAccount, error) {
	var account models.OauthAccount
	if err := o.db.Where("user_id = ?", userID).First(&account).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get OAuth account: %w", err)
	}
	return &account, nil
}

func (o *OauthAccountRepository) CreateOauthAccount(ctx context.Context, account *models.OauthAccount) error {
	if err := o.db.Create(account).Error; err != nil {
		return fmt.Errorf("failed to create OAuth account: %w", err)
	}
	return nil
}

func (o *OauthAccountRepository) UpdateOauthAccount(ctx context.Context, account *models.OauthAccount) error {
	if err := o.db.Model(&models.OauthAccount{}).Where("user_id = ?", account.UserID).Updates(account).Error; err != nil {
		return fmt.Errorf("failed to update OAuth account: %w", err)
	}
	return nil
}

func (o *OauthAccountRepository) DeleteOauthAccount(ctx context.Context, account *models.OauthAccount) error {
	if err := o.db.Delete(account).Error; err != nil {
		return fmt.Errorf("failed to delete OAuth account: %w", err)
	}
	return nil
}
