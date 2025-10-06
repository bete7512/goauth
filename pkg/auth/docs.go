package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/docs/swagger"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// GenerateSwaggerDocs dynamically generates docs for enabled modules only
func (a *Auth) GenerateSwaggerDocs(cfg types.SwaggerConfig) ([]byte, error) {
	if !a.initialized {
		return nil, errors.New("auth must be initialized before generating swagger docs")
	}

	modules := make([]config.Module, 0, len(a.modules))
	for _, module := range a.modules {
		modules = append(modules, module)
	}

	gen := swagger.NewGenerator(modules, cfg)
	return gen.MergeEnabledModules()
}

// EnableSwagger adds swagger UI and spec endpoints
func (a *Auth) EnableSwagger(cfg types.SwaggerConfig) error {
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

	spec, err := a.GenerateSwaggerDocs(cfg)
	if err != nil {
		a.moduleDependencies.Logger.Error("failed to generate swagger", "error", err)
		return fmt.Errorf("failed to generate swagger: %w", err)
	}

	path := "/" + strings.Trim(cfg.Path, "/")
	// Add swagger routes
	swaggerRoutes := []config.RouteInfo{
		{
			Name:   "swagger.spec",
			Path:   path + "/openapi.yaml",
			Method: "GET",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/yaml")
				w.Write(spec)
			},
		},
		{
			Name:    "swagger.ui",
			Path:    path,
			Method:  "GET",
			Handler: swagger.ServeSwaggerUI(path + "/openapi.yaml"),
		},
	}

	// Add to routes
	a.routes = append(a.routes, swaggerRoutes...)
	return nil
}
