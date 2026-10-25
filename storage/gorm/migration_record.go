package gorm

import "time"

// gormMigrationRecord is the internal GORM model for the goauth_migrations tracking table.
// It is NOT part of the public API — use types.MigrationRecord for that.
type gormMigrationRecord struct {
	Checksum string `gorm:"column:checksum"`
	Dirty    bool   `gorm:"column:dirty;not null;default:false"`
	ID       string `gorm:"primaryKey"`
	// Indexed string columns need an explicit size: GORM maps unsized strings to
	// longtext on MySQL, which cannot be part of a key (error 1170).
	ModuleName string    `gorm:"column:module_name;size:191;not null;uniqueIndex:idx_module_version_unique"`
	Version    int       `gorm:"column:version;not null;uniqueIndex:idx_module_version_unique"`
	Name       string    `gorm:"column:name;not null"`
	Dialect    string    `gorm:"column:dialect;not null"`
	AppliedAt  time.Time `gorm:"column:applied_at;not null"`
}

func (gormMigrationRecord) TableName() string {
	return "goauth_migrations"
}
