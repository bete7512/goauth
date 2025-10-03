package storage

import (
	"fmt"

	"github.com/bete7512/goauth/internal/storage/gorm"
	"github.com/bete7512/goauth/pkg/config"
)

// NewStorage creates a storage instance based on the configuration
func NewStorage(config config.StorageConfig) (config.Storage, error) {
	// If custom storage is provided, use it
	if config.CustomStorage != nil {
		return config.CustomStorage, nil
	}

	// Create storage based on driver
	switch config.Driver {
	case "gorm":
		return newGormStorage(config)
	case "mongo":
		return nil, fmt.Errorf("mongo storage not implemented yet")
	case "sqlc":
		return nil, fmt.Errorf("sqlc storage not implemented yet")
	// TODO: continue with other storage drivers
	default:
		return nil, fmt.Errorf("unsupported storage driver: %s", config.Driver)
	}
}

// newGormStorage is a placeholder - actual implementation is in internal/storage/gorm
// This function should be registered by the gorm storage package
var newGormStorage = func(config config.StorageConfig) (config.Storage, error) {
	return gorm.NewFromConfig(config)
}

// Helper to safely cast repositories
func GetTypedRepository[T any](storage config.Storage, name string) (T, error) {
	var zero T
	repo := storage.GetRepository(name)
	if repo == nil {
		return zero, fmt.Errorf("repository %s not found", name)
	}

	typed, ok := repo.(T)
	if !ok {
		return zero, fmt.Errorf("repository %s is not of expected type", name)
	}

	return typed, nil
}

// GetTypedRepositoryFromTx is similar but for transactions
func GetTypedRepositoryFromTx[T any](tx config.Transaction, name string) (T, error) {
	var zero T
	repo := tx.GetRepository(name)
	if repo == nil {
		return zero, fmt.Errorf("repository %s not found in transaction", name)
	}

	typed, ok := repo.(T)
	if !ok {
		return zero, fmt.Errorf("repository %s is not of expected type", name)
	}

	return typed, nil
}
