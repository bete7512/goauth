// auth/database/client.go
package database

import (
	"fmt"

	"github.com/bete7512/goauth/pkg/config"
)

type DBClient interface {
	Connect() error
	Close() error
	GetDB() interface{}
}

func NewDBClient(conf config.Config) (DBClient, error) {
	switch conf.Database.Type {
	case config.PostgreSQL:
		return &PostgresClient{Config: &conf, URL: conf.Database.URL, AutoMigrate: conf.Database.AutoMigrate}, nil
	case config.MySQL:
		return &MySQLClient{Config: &conf, URL: conf.Database.URL, AutoMigrate: conf.Database.AutoMigrate}, nil
	case config.MongoDB:
		return &MongoDBClient{Config: &conf, URL: conf.Database.URL, AutoMigrate: conf.Database.AutoMigrate}, nil
	default:
		return nil, fmt.Errorf("unsupported database type: %s", conf.Database.Type)
	}
}
