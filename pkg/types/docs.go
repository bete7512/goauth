package types

// SwaggerSecurityScheme defines an OpenAPI security scheme
type SwaggerSecurityScheme struct {
	Type         string                 // apiKey, http, oauth2, openIdConnect
	In           string                 // query, header, cookie (for apiKey)
	Name         string                 // Name of the header, query, or cookie (for apiKey)
	Scheme       string                 // bearer, basic, etc. (for http type)
	BearerFormat string                 // JWT, etc. (for bearer scheme)
	Description  string                 // Description of the security scheme
	Flows        map[string]interface{} // OAuth2 flows (for oauth2 type)
}

type SwaggerConfig struct {
	Title           string
	Path            string
	Description     string
	Version         string
	Servers         []SwaggerServer
	SecuritySchemes map[string]SwaggerSecurityScheme // Custom security schemes (optional)
	UseDefaultAuth  bool                             // Use default auth based on SecurityConfig.AuthMode
}

type SwaggerServer struct {
	URL         string
	Description string
}
