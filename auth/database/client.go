// auth/database/client.go
package database

import (
	"fmt"

	"github.com/bete7512/go-auth/auth/models"
	"github.com/bete7512/go-auth/auth/types"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type DBClient interface {
	Connect() error
	Close() error
	GetDB() *gorm.DB
}

type PostgresClient struct {
	Config      *types.DatabaseConfig
	DB          *gorm.DB
	URL         string
	AutoMigrate bool
}

func NewDBClient(config types.DatabaseConfig) (DBClient, error) {
	switch config.Type {
	case types.PostgreSQL:
		return &PostgresClient{URL: config.URL, AutoMigrate: config.AutoMigrate}, nil
	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}
}

func (c *PostgresClient) Connect() error {
	db, err := gorm.Open(postgres.Open(c.URL), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	if err := db.AutoMigrate(
		&models.User{},
		&models.Session{},
	); err != nil {
		return fmt.Errorf("failed to auto-migrate: %w", err)
	}

	c.DB = db
	return nil
}

func (c *PostgresClient) Close() error {
	if c.DB != nil {
		sqlDB, err := c.DB.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}

func (c *PostgresClient) GetDB() *gorm.DB {
	return c.DB
}
