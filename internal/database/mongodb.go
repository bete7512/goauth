package database

import (
	"context"
	"fmt"

	"github.com/bete7512/goauth/pkg/config"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDBClient struct {
	Config      *config.Config
	DB          *mongo.Client
	URL         string
	AutoMigrate bool
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
		// Create collections if they don't exist
		database := client.Database("goauth")
		collections := []string{"users", "tokens", "sessions", "audit_logs", "totp_secrets", "oauth_accounts", "backup_codes"}

		for _, collectionName := range collections {
			err := database.CreateCollection(context.TODO(), collectionName)
			if err != nil {
				// Collection might already exist, which is fine
				// We could check for specific error types here if needed
			}
		}
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
