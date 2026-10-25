package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/docs/openapi"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// GenerateOpenAPIDocs dynamically generates docs for enabled modules only
func (a *Auth) GenerateOpenAPIDocs(cfg types.OpenAPIConfig) ([]byte, error) {
	if !a.initialized.Load() {
		return nil, errors.New("auth must be initialized before generating openapi docs")
	}

	modules := make([]config.Module, 0, len(a.modules))
	for _, name := range a.moduleOrder {
		modules = append(modules, a.modules[name])
	}

	gen := openapi.NewGenerator(modules, cfg)
	return gen.MergeEnabledModules()
}

// OpenAPI adds the OpenAPI UI and spec endpoints
func (a *Auth) OpenAPI(cfg types.OpenAPIConfig) error {
	basePath := strings.TrimRight(a.config.BasePath, "/")
	if len(cfg.Servers) == 0 {
		return fmt.Errorf("no servers provided")
	}
	for i := range cfg.Servers {
		if err := utils.ValidateUrl(cfg.Servers[i].URL); err != nil {
			return fmt.Errorf("invalid url: %v", err)
		}
		cfg.Servers[i].URL = strings.TrimRight(cfg.Servers[i].URL, "/") + basePath
	}

	spec, err := a.GenerateOpenAPIDocs(cfg)
	if err != nil {
		a.moduleDependencies.Logger.Error("failed to generate openapi docs", "error", err)
		return fmt.Errorf("failed to generate openapi docs: %w", err)
	}

	path := "/" + strings.Trim(cfg.Path, "/")
	openapiRoutes := []config.RouteInfo{
		{
			Name:   "openapi.spec",
			Path:   path + "/openapi.yaml",
			Method: "GET",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/yaml")
				_, _ = w.Write(spec)
			},
		},
		{
			Name:    "openapi.ui",
			Path:    path,
			Method:  "GET",
			Handler: openapi.ServeOpenAPIUI(path + "/openapi.yaml"),
		},
	}

	a.registryMu.Lock()
	defer a.registryMu.Unlock()
	previous := a.routes
	a.routes = append(append([]config.RouteInfo(nil), a.routes...), openapiRoutes...)
	if err := a.validateRoutes(); err != nil {
		a.routes = previous
		return err
	}
	return nil
}
