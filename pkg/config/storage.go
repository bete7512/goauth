package config

import "github.com/bete7512/goauth/pkg/interfaces"

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
