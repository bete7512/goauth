package repositories

import (
	"fmt"

	// import cycle not allowedgo list
	"github.com/bete7512/go-auth/auth/interfaces"
	"github.com/bete7512/go-auth/auth/repositories/postgres"
	"github.com/bete7512/go-auth/auth/types"
	"gorm.io/gorm"
)

func NewRepositoryFactory(dbType types.DatabaseType, db interface{}) (interfaces.RepositoryFactory, error) {
	switch dbType {
	case types.PostgreSQL:
		gormDB, ok := db.(*gorm.DB)
		if !ok {
			return nil, fmt.Errorf("invalid database connection for PostgreSQL")
		}
		return postgres.NewRepositoryFactory(gormDB), nil
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}
}
