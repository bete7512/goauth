package gorm

import "time"

// gormMigrationRecord is the internal GORM model for the goauth_migrations tracking table.
// It is NOT part of the public API — use types.MigrationRecord for that.
type gormMigrationRecord struct {
	ID         string    `gorm:"primaryKey"`
	ModuleName string    `gorm:"column:module_name;not null;index"`
	Dialect    string    `gorm:"column:dialect;not null"`
	AppliedAt  time.Time `gorm:"column:applied_at;not null"`
	Status     string    `gorm:"column:status;not null;default:'up'"`
}

func (gormMigrationRecord) TableName() string {
	return "goauth_migrations"
}
