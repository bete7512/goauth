package database

import (
	"fmt"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type MariaDBClient struct {
	Config      *config.Config
	DB          *gorm.DB
	URL         string
	AutoMigrate bool
}

func (c *MariaDBClient) Connect() error {
	db, err := gorm.Open(mysql.Open(c.URL), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to MariaDB: %w", err)
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
			err := db.Exec(`ALTER TABLE users MODIFY COLUMN phone_number VARCHAR(255) NOT NULL`).Error
			if err != nil {
				return fmt.Errorf("failed to alter phone_number column: %w", err)
			}
		}
		if c.Config.AuthConfig.Methods.PhoneVerification.UniquePhoneNumber {
			err := db.Exec(`ALTER TABLE users ADD CONSTRAINT unique_phone_number UNIQUE (phone_number)`).Error
			if err != nil {
				return fmt.Errorf("failed to add unique constraint to phone_number column: %w", err)
			}
		}
	}

	c.DB = db
	return nil
}

func (c *MariaDBClient) Close() error {
	if c.DB != nil {
		sqlDB, err := c.DB.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}

func (c *MariaDBClient) GetDB() interface{} {
	return c.DB
}
