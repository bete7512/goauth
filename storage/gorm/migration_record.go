package gorm

import "time"

// gormMigrationRecord is the internal GORM model for the goauth_migrations tracking table.
// It is NOT part of the public API — use types.MigrationRecord for that.
type gormMigrationRecord struct {
	ID         string    `gorm:"primaryKey"`
	ModuleName string    `gorm:"column:module_name;not null;index:idx_module_version"`
	Version    int       `gorm:"column:version;not null;index:idx_module_version"`
	Name       string    `gorm:"column:name;not null"`
	Dialect    string    `gorm:"column:dialect;not null"`
	AppliedAt  time.Time `gorm:"column:applied_at;not null"`
}

func (gormMigrationRecord) TableName() string {
	return "goauth_migrations"
}
