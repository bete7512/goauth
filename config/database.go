package config
type DatabaseConfig struct {
	Type        DatabaseType
	URL         string
	AutoMigrate bool
	
	// Custom storage
	EnableCustomRepository bool
	RepositoryFactory      CustomStorageRepositoryConfig
}
