package auth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/bete7512/goauth/internal/docs/swagger"
	"github.com/bete7512/goauth/pkg/config"
)

// GenerateSwaggerDocs dynamically generates docs for enabled modules only
func (a *Auth) GenerateSwaggerDocs() ([]byte, error) {
	if !a.initialized {
		return nil, errors.New("auth must be initialized before generating swagger docs")
	}

	modules := make([]config.Module, 0, len(a.modules))
	for _, module := range a.modules {
		modules = append(modules, module)
	}
	gen := swagger.NewGenerator(modules)
	return gen.MergeEnabledModules()
}

// EnableSwagger adds swagger UI and spec endpoints
func (a *Auth) EnableSwagger() error {
	spec, err := a.GenerateSwaggerDocs()
	if err != nil {
		return fmt.Errorf("failed to generate swagger: %w", err)
	}

	// Add swagger routes
	swaggerRoutes := []config.RouteInfo{
		{
			Name:   "swagger.spec",
			Path:   "/swagger/openapi.yaml",
			Method: "GET",
			Handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/yaml")
				w.Write(spec)
			},
		},
		{
			Name:    "swagger.ui",
			Path:    "/swagger/",
			Method:  "GET",
			Handler: swagger.ServeSwaggerUI("/swagger/openapi.yaml"),
		},
	}

	// Add to routes
	a.routes = append(a.routes, swaggerRoutes...)
	return nil
}
