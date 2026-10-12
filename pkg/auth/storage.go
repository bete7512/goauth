package auth

import (
	"fmt"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type boundStorage struct {
	types.Storage
	core    types.CoreStorage
	session types.SessionStorage
}

func (s *boundStorage) Core() types.CoreStorage       { return s.core }
func (s *boundStorage) Session() types.SessionStorage { return s.session }

func (a *Auth) resolveStorage() error {
	s := &boundStorage{Storage: a.storage, core: a.storage.Core(), session: a.storage.Session()}
	coreOwner, sessionOwner := "", ""
	if a.config.Core != nil && a.config.Core.CustomStorage != nil {
		s.core = a.config.Core.CustomStorage
		coreOwner = "core"
	}
	for _, name := range a.moduleOrder {
		module, ok := a.modules[name].(config.StorageBindingModule)
		if !ok {
			continue
		}
		bindings := module.StorageBindings()
		if bindings.Core != nil {
			if coreOwner != "" {
				return fmt.Errorf("conflicting core stores from %s and %s", coreOwner, name)
			}
			s.core, coreOwner = bindings.Core, name
		}
		if bindings.Session != nil {
			if sessionOwner != "" {
				return fmt.Errorf("conflicting session stores from %s and %s", sessionOwner, name)
			}
			s.session, sessionOwner = bindings.Session, name
		}
	}
	if s.core == nil || s.core.Users() == nil || s.core.Tokens() == nil {
		return fmt.Errorf("core user and token storage required")
	}
	if a.config.Security.AuthStrategy == types.StrategySession && s.session == nil {
		return fmt.Errorf("session storage required")
	}
	if coreOwner != "" || sessionOwner != "" {
		a.config.Storage = s
		a.moduleDependencies.Storage = s
	}
	return nil
}
