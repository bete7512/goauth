package models

//go:generate mockgen -destination=../../internal/mocks/mock_twofactor_repository.go -package=mocks github.com/bete7512/goauth/pkg/models TwoFactorRepository,BackupCodeRepository,ReplayGuardedTwoFactorRepository

import "context"

// TwoFactorRepository handles 2FA configuration persistence
type TwoFactorRepository interface {
	Create(ctx context.Context, tf *TwoFactor) error
	GetByUserID(ctx context.Context, userID string) (*TwoFactor, error)
	Update(ctx context.Context, tf *TwoFactor) error
	Delete(ctx context.Context, userID string) error
}

// TOTPStepConsumer is an optional repository capability. ConsumeTOTPStep
// records that the code for TOTP time step `step` was accepted, atomically:
// it succeeds only when step is greater than the stored last_used_step and
// returns ErrConflict otherwise (a replayed or older code). On success it also
// clears the failed-attempt counter and lockout. Exactly one of several
// concurrent callers for the same step succeeds.
type TOTPStepConsumer interface {
	ConsumeTOTPStep(ctx context.Context, userID string, step int64) error
}

// ReplayGuardedTwoFactorRepository is a TwoFactorRepository with atomic step
// consumption. The GORM repository implements it; custom stores should too.
type ReplayGuardedTwoFactorRepository interface {
	TwoFactorRepository
	TOTPStepConsumer
}

// BackupCodeRepository handles backup code persistence
type BackupCodeRepository interface {
	CreateBatch(ctx context.Context, codes []*BackupCode) error
	GetByUserID(ctx context.Context, userID string) ([]*BackupCode, error)
	GetUnusedByUserID(ctx context.Context, userID string) ([]*BackupCode, error)
	// MarkUsed atomically consumes an unused code; replay returns ErrConflict.
	MarkUsed(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID string) error
}
