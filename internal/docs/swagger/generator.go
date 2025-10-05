package swagger

import (
	"fmt"
	"net/http"

	"github.com/bete7512/goauth/pkg/config"
	"gopkg.in/yaml.v3"
)

type SwaggerGenerator struct {
	modules  []config.Module
	baseSpec map[string]interface{}
}

func NewGenerator(modules []config.Module, metadata config.SwaggerConfig) *SwaggerGenerator {
	return &SwaggerGenerator{
		modules:  modules,
		baseSpec: getBaseSpec(metadata),
	}
}

// MergeEnabledModules only merges specs from enabled modules
func (g *SwaggerGenerator) MergeEnabledModules() ([]byte, error) {
	merged := copyMap(g.baseSpec)

	// Initialize structures
	if merged["paths"] == nil {
		merged["paths"] = make(map[string]interface{})
	}
	if merged["components"] == nil {
		merged["components"] = make(map[string]interface{})
	}

	// Iterate through ONLY registered modules
	for _, module := range g.modules {
		spec := module.SwaggerSpec()
		if len(spec) == 0 {
			continue // Skip modules without swagger specs
		}

		moduleSpec := make(map[string]interface{})
		if err := yaml.Unmarshal(spec, &moduleSpec); err != nil {
			return nil, fmt.Errorf("failed to parse swagger for module %s: %w", module.Name(), err)
		}

		// Merge paths
		if paths, ok := moduleSpec["paths"].(map[string]interface{}); ok {
			mergePaths := merged["paths"].(map[string]interface{})
			for path, spec := range paths {
				mergePaths[path] = spec
			}
		}

		// Merge components (schemas, security schemes, etc.)
		if comps, ok := moduleSpec["components"].(map[string]interface{}); ok {
			mergeComponents(merged["components"].(map[string]interface{}), comps)
		}

		// Merge tags
		if tags, ok := moduleSpec["tags"].([]interface{}); ok {
			if merged["tags"] == nil {
				merged["tags"] = []interface{}{}
			}
			merged["tags"] = append(merged["tags"].([]interface{}), tags...)
		}
	}

	return yaml.Marshal(merged)
}

func mergeComponents(base, new map[string]interface{}) {
	for key, value := range new {
		if baseValue, exists := base[key]; exists {
			// Merge if both are maps
			if baseMap, ok := baseValue.(map[string]interface{}); ok {
				if newMap, ok := value.(map[string]interface{}); ok {
					for k, v := range newMap {
						baseMap[k] = v
					}
					continue
				}
			}
		}
		base[key] = value
	}
}

func getBaseSpec(metadata config.SwaggerConfig) map[string]interface{} {
	return map[string]interface{}{
		"openapi": "3.0.3",
		"info": map[string]interface{}{
			"title":       metadata.Title,
			"description": metadata.Description,
			"version":     metadata.Version,
		},
		"servers": func() []interface{} {
			servers := make([]interface{}, len(metadata.Servers))
			for i, server := range metadata.Servers {
				servers[i] = map[string]interface{}{
					"url":         server.URL,
					"description": server.Description,
				}
			}
			return servers
		}(),
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"sessionAuth": map[string]interface{}{
					"type": "apiKey",
					"in":   "cookie",
					"name": "session_token",
				},
			},
		},
	}
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	copy := make(map[string]interface{})
	for k, v := range m {
		copy[k] = v
	}
	return copy
}

// ServeSwaggerUI serves embedded Swagger UI
func ServeSwaggerUI(specPath string) http.HandlerFunc {
	swaggerHTML := `<!DOCTYPE html>
<html>
<head>
    <title>Go-Auth API Documentation</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({
            url: '` + specPath + `',
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [SwaggerUIBundle.presets.apis]
        })
    </script>
</body>
</html>`
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(swaggerHTML))
	}
}
