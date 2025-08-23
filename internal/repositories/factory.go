package repositories

import (
	"fmt"

	"github.com/bete7512/goauth/internal/repositories/mongodb"
	"github.com/bete7512/goauth/internal/repositories/mysql"
	"github.com/bete7512/goauth/internal/repositories/postgres"
	"github.com/bete7512/goauth/internal/repositories/sqlserver"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
	"go.mongodb.org/mongo-driver/mongo"
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
	case config.MySQL:
		gormDB, ok := db.(*gorm.DB)
		if !ok {
			return nil, fmt.Errorf("invalid database connection for MySQL")
		}
		return mysql.NewRepositoryFactory(gormDB), nil
	case config.MariaDB:
		gormDB, ok := db.(*gorm.DB)
		if !ok {
			return nil, fmt.Errorf("invalid database connection for MariaDB")
		}
		return mysql.NewRepositoryFactory(gormDB), nil
	case config.SQLite:
		gormDB, ok := db.(*gorm.DB)
		if !ok {
			return nil, fmt.Errorf("invalid database connection for SQLite")
		}
		return mysql.NewRepositoryFactory(gormDB), nil
	case config.MongoDB:
		mongoClient, ok := db.(*mongo.Client)
		if !ok {
			return nil, fmt.Errorf("invalid database connection for MongoDB")
		}
		return mongodb.NewRepositoryFactory(mongoClient), nil
	case config.SQLServer:
		gormDB, ok := db.(*gorm.DB)
		if !ok {
			return nil, fmt.Errorf("invalid database connection for SQL Server")
		}
		return sqlserver.NewRepositoryFactory(gormDB), nil
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}
}
