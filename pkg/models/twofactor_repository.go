package models

import "context"

// TwoFactorRepository handles 2FA configuration persistence
type TwoFactorRepository interface {
	Create(ctx context.Context, tf *TwoFactor) error
	GetByUserID(ctx context.Context, userID string) (*TwoFactor, error)
	Update(ctx context.Context, tf *TwoFactor) error
	Delete(ctx context.Context, userID string) error
}

// BackupCodeRepository handles backup code persistence
type BackupCodeRepository interface {
	CreateBatch(ctx context.Context, codes []*BackupCode) error
	GetByUserID(ctx context.Context, userID string) ([]*BackupCode, error)
	GetUnusedByUserID(ctx context.Context, userID string) ([]*BackupCode, error)
	MarkUsed(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID string) error
}
