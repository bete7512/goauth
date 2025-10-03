package core_services

import "github.com/bete7512/goauth/pkg/config"

type CoreService struct {
	deps config.ModuleDependencies
	// Logger logger.Log
	// inject storages
	// Storage storage.Storage
}

func NewCoreService(deps config.ModuleDependencies) *CoreService {
	return &CoreService{
		deps: deps,
	}
}

// implement service methods here
