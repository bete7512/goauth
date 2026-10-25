package types

// OpenAPISecurityScheme defines an OpenAPI security scheme
type OpenAPISecurityScheme struct {
	Type         string                 // apiKey, http, oauth2, openIdConnect
	In           string                 // query, header, cookie (for apiKey)
	Name         string                 // Name of the header, query, or cookie (for apiKey)
	Scheme       string                 // bearer, basic, etc. (for http type)
	BearerFormat string                 // JWT, etc. (for bearer scheme)
	Description  string                 // Description of the security scheme
	Flows        map[string]interface{} // OAuth2 flows (for oauth2 type)
}

// OpenAPIConfig configures the generated OpenAPI document and its UI.
type OpenAPIConfig struct {
	Title           string
	Path            string
	Description     string
	Version         string
	Servers         []OpenAPIServer
	SecuritySchemes map[string]OpenAPISecurityScheme // Custom security schemes (optional)
	UseDefaultAuth  bool                             // Use default auth based on SecurityConfig.AuthMode
}

// OpenAPIServer is a server entry in the OpenAPI document.
type OpenAPIServer struct {
	URL         string
	Description string
}
