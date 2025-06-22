package config

import "github.com/bete7512/goauth/interfaces"

type CustomStorageRepositoryConfig struct {
	Factory interfaces.RepositoryFactory
}

type RedisConfig struct {
	Host     string
	Port     int
	Database int
	Password string
}
