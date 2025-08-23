package config

import (
	"time"

	"github.com/bete7512/goauth/pkg/interfaces"
)

type DatabaseConfig struct {
	Type        DatabaseType
	URL         string
	AutoMigrate bool

	// Custom storage
	EnableCustomRepository bool
	RepositoryFactory      CustomStorageRepositoryConfig
}

type CustomStorageRepositoryConfig struct {
	Factory interfaces.RepositoryFactory
}

type RedisConfig struct {
	Host     string
	Port     int
	Database int
	Password string
}

// CacheConfig defines the configuration for caching
type CacheConfig struct {
	Type CacheType
	// Redis configuration (used when Type is RedisCache)
	Redis RedisConfig
	// Valkey configuration (used when Type is ValkeyCache)
	Valkey ValkeyConfig
	// Custom cache configuration
	EnableCustomCache bool
	CustomCache       CustomCacheConfig
	// Global cache settings
	DefaultTTL time.Duration
	Enabled    bool
}

// ValkeyConfig defines configuration for Valkey cache
type ValkeyConfig struct {
	Host     string
	Port     int
	Database int
	Password string
}

// CustomCacheConfig defines configuration for custom cache implementations
type CustomCacheConfig struct {
	Factory interfaces.CacheFactory
}
