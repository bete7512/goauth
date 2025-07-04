package postgres

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type OauthAccountRepository struct {
	Db *gorm.DB
}

func NewOauthAccountRepository(db *gorm.DB) *OauthAccountRepository {
	return &OauthAccountRepository{Db: db}
}

func (r *OauthAccountRepository) GetOauthAccountByUserID(ctx context.Context, userID string) (*models.OauthAccount, error) {
	var oauthAccount models.OauthAccount
	if err := r.Db.WithContext(ctx).Where("user_id = ?", userID).First(&oauthAccount).Error; err != nil {
		return nil, err
	}
	return &oauthAccount, nil
}

func (r *OauthAccountRepository) CreateOauthAccount(ctx context.Context, account *models.OauthAccount) error {
	return r.Db.WithContext(ctx).Create(account).Error
}

func (r *OauthAccountRepository) UpdateOauthAccount(ctx context.Context, account *models.OauthAccount) error {
	return r.Db.WithContext(ctx).Save(account).Error
}

func (r *OauthAccountRepository) DeleteOauthAccount(ctx context.Context, account *models.OauthAccount) error {
	return r.Db.WithContext(ctx).Delete(account).Error
}
