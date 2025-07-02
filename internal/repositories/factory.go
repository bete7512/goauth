package repositories

import (
	"fmt"
	"github.com/bete7512/goauth/internal/repositories/postgres"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
	"gorm.io/gorm"
)

func NewRepositoryFactory(dbType config.DatabaseType, db interface{}) (interfaces.RepositoryFactory, error) {
	switch dbType {
	case config.PostgreSQL:
		gormDB, ok := db.(*gorm.DB)
		if !ok {
			return nil, fmt.Errorf("invalid database connection for PostgreSQL")
		}
		return postgres.NewRepositoryFactory(gormDB), nil
	case config.MongoDB:
		// mongoClient, ok := db.(*mongo.Client)
		// if !ok {
		// 	return nil, fmt.Errorf("invalid database connection for MongoDB")
		// }
		// // You need to create a MongoDB repository factory implementation
		// return mongodb.NewRepositoryFactory(mongoClient), nil
		// TODO: continue implementing other database types
		return nil, fmt.Errorf("MongoDB not implemented")
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}
}
