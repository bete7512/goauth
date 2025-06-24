// auth/database/client.go
package database

import (
	"context"
	"fmt"

	"github.com/bete7512/goauth/config"
	"github.com/bete7512/goauth/models"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type DBClient interface {
	Connect() error
	Close() error
	GetDB() interface{}
}

type PostgresClient struct {
	Config      *config.Config
	DB          *gorm.DB
	URL         string
	AutoMigrate bool
}

type MySQLClient struct {
	Config      *config.DatabaseConfig
	DB          *gorm.DB
	URL         string
	AutoMigrate bool
}

type MongoDBClient struct {
	Config      *config.DatabaseConfig
	DB          *mongo.Client
	URL         string
	AutoMigrate bool
}

func NewDBClient(conf config.Config) (DBClient, error) {
	switch conf.Database.Type {
	case config.PostgreSQL:
		return &PostgresClient{Config: &conf, URL: conf.Database.URL, AutoMigrate: conf.Database.AutoMigrate}, nil
	case config.MySQL:
		return &MySQLClient{Config: &conf.Database, URL: conf.Database.URL, AutoMigrate: conf.Database.AutoMigrate}, nil
	case config.MongoDB:
		return &MongoDBClient{Config: &conf.Database, URL: conf.Database.URL, AutoMigrate: conf.Database.AutoMigrate}, nil
	default:
		return nil, fmt.Errorf("unsupported database type: %s", conf.Database.Type)
	}
}

func (c *PostgresClient) Connect() error {
	db, err := gorm.Open(postgres.Open(c.URL), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	if c.AutoMigrate {
		if err := db.AutoMigrate(
			&models.User{},
			&models.Token{},
		); err != nil {
			return fmt.Errorf("failed to auto-migrate: %w", err)
		}

		if c.Config.AuthConfig.Methods.PhoneVerification.PhoneColumnRequired {
			err := db.Exec(`ALTER TABLE users ALTER COLUMN phone_number SET NOT NULL`).Error
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

func (c *PostgresClient) GetDB() interface{} {
	return c.DB
}

func (c *MySQLClient) Connect() error {
	db, err := gorm.Open(mysql.Open(c.URL), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to MySQL: %w", err)
	}
	if c.AutoMigrate {
		if err := db.AutoMigrate(
			&models.User{},
			&models.Token{},
		); err != nil {
			return fmt.Errorf("failed to auto-migrate: %w", err)
		}
	}

	c.DB = db
	return nil
}

func (c *MySQLClient) Close() error {
	if c.DB != nil {
		sqlDB, err := c.DB.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}

func (c *MySQLClient) GetDB() interface{} {
	return c.DB
}

func (c *MongoDBClient) Connect() error {
	// Set client options
	clientOptions := options.Client().ApplyURI(c.URL)

	// Connect to MongoDB
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		return fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	c.DB = client
	if c.AutoMigrate {
		// TODO: do some research on MongoDB migrations
		// at least check if the collections exist and create them if they don't exist
	}

	return nil
}

func (c *MongoDBClient) Close() error {
	if c.DB != nil {
		return c.DB.Disconnect(context.TODO())
	}
	return nil
}

func (c *MongoDBClient) GetDB() interface{} {
	return c.DB
}
