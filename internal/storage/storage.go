package storage

import (
	"fmt"

	"github.com/bete7512/goauth/internal/storage/gorm"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// NewStorage creates a storage instance based on the configuration
// This is the main factory function that users call to create storage
func NewStorage(cfg config.StorageConfig) (config.Storage, error) {

	// Create storage based on driver
	switch cfg.Driver {
	case types.DriverTypeGorm:
		return gorm.NewFromConfig(cfg)
	case types.DriverTypeMongo:
		return nil, fmt.Errorf("mongo storage not implemented yet")
	case types.DriverTypeSqlc:
		return nil, fmt.Errorf("sqlc storage not implemented yet")
	default:
		return nil, fmt.Errorf("unsupported storage driver: %s", cfg.Driver)
	}
}
