package storage

import (
	"time"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/bete7512/goauth/storage/cache/memory"
	storage_gorm "github.com/bete7512/goauth/storage/gorm"
	"gorm.io/gorm"
)

func NewGormStorage(config storage_gorm.Config) (types.Storage, error) {
	return storage_gorm.NewStorage(config)
}

// NewGormStorageFromDB creates a new GORM-based storage from an existing *gorm.DB
// Use this if you already have a database connection
func NewGormStorageFromDB(db *gorm.DB) types.Storage {
	return storage_gorm.NewStorageFromDB(db)
}

// NewMemoryCache creates an in-memory cache for single-instance deployments
// For distributed systems, use Redis or similar
func NewMemoryCache(cleanupInterval time.Duration) types.Cache {
	return memory.NewMemoryCache(cleanupInterval)
}

// GormConfig re-exports gorm.Config for convenience
type GormConfig = storage_gorm.Config
