package openapi

import "strings"

// NamespaceComponents keeps module-local schemas and parameters distinct.
// Security schemes remain application-wide and are selected by the host.
func NamespaceComponents(module string, spec map[string]interface{}) {
	components, ok := spec["components"].(map[string]interface{})
	if !ok {
		return
	}
	replacements := map[string]string{}
	prefix := strings.ToUpper(module[:1]) + module[1:]
	for kind, raw := range components {
		if kind == "securitySchemes" {
			schemes, _ := raw.(map[string]interface{})
			delete(schemes, "bearerAuth")
			delete(schemes, "cookieAuth")
			continue
		}
		items, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		renamed := make(map[string]interface{}, len(items))
		for name, value := range items {
			qualified := prefix + name
			replacements["#/components/"+kind+"/"+name] = "#/components/" + kind + "/" + qualified
			renamed[qualified] = value
		}
		components[kind] = renamed
	}
	var rewrite func(interface{})
	rewrite = func(value interface{}) {
		switch typed := value.(type) {
		case map[string]interface{}:
			if ref, ok := typed["$ref"].(string); ok {
				if replacement, exists := replacements[ref]; exists {
					typed["$ref"] = replacement
				}
			}
			for _, child := range typed {
				rewrite(child)
			}
		case []interface{}:
			for _, child := range typed {
				rewrite(child)
			}
		}
	}
	rewrite(spec)
}
