package csrf

import (
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type CSRFManager struct {
	Conf config.Config
}

func New(conf config.Config) (interfaces.CSRFManager, error) {
	switch conf.Security.CSRF.Type {
	case config.MemoryCSRF:
		csrfManager, err := NewMemoryCSRFManager(conf)
		if err != nil {
			return nil, err
		}
		return csrfManager, nil
	case config.RedisCSRF:
		csrfManager, err := NewRedisCSRFManager(conf)
		if err != nil {
			return nil, err
		}
		return csrfManager, nil
	default:
		csrfManager, err := NewMemoryCSRFManager(conf)
		if err != nil {
			return nil, err
		}
		return csrfManager, nil
	}
}
