package database

import (
	"fmt"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type SQLiteClient struct {
	Config      *config.Config
	DB          *gorm.DB
	URL         string
	AutoMigrate bool
}

func (c *SQLiteClient) Connect() error {
	db, err := gorm.Open(sqlite.Open(c.URL), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to SQLite: %w", err)
	}
	if c.AutoMigrate {
		if err := db.AutoMigrate(
			&models.User{},
			&models.Token{},
			&models.Session{},
			&models.AuditLog{},
			&models.TotpSecret{},
			&models.OauthAccount{},
			&models.BackupCode{},
		); err != nil {
			return fmt.Errorf("failed to auto-migrate: %w", err)
		}

		if c.Config.AuthConfig.Methods.PhoneVerification.PhoneColumnRequired {
			err := db.Exec(`ALTER TABLE users ADD COLUMN phone_number TEXT NOT NULL DEFAULT ''`).Error
			if err != nil {
				return fmt.Errorf("failed to alter phone_number column: %w", err)
			}
		}
		if c.Config.AuthConfig.Methods.PhoneVerification.UniquePhoneNumber {
			err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone_number ON users(phone_number)`).Error
			if err != nil {
				return fmt.Errorf("failed to add unique constraint to phone_number column: %w", err)
			}
		}
	}

	c.DB = db
	return nil
}

func (c *SQLiteClient) Close() error {
	if c.DB != nil {
		sqlDB, err := c.DB.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}

func (c *SQLiteClient) GetDB() interface{} {
	return c.DB
}
