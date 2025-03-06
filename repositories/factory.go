package repositories

import (
	"fmt"

	// import cycle not allowedgo list
	"github.com/bete7512/goauth/interfaces"
	"github.com/bete7512/goauth/repositories/postgres"
	"github.com/bete7512/goauth/types"
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
	// TODO: continue implementing other database types
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}
}
