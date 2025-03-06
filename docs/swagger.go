// // auth/docs/swagger.go
package docs

// import (
// 	"embed"
// 	"fmt"
// 	"log"
// 	"net/http"
// 	"os"
// 	"path/filepath"
// 	"strings"

// 	"github.com/bete7512/goauth/types"
// 	"github.com/getkin/kin-openapi/openapi3"
// 	"github.com/gin-gonic/gin"
// 	ginSwagger "github.com/swaggo/gin-swagger"
// 	swaggerFiles "github.com/swaggo/files"
// 	"github.com/swaggo/swag"
// )

// var swaggerUIFiles embed.FS

// // SwaggerInfo holds the API metadata needed for the OpenAPI spec
// var SwaggerInfo = struct {
// 	Version     string
// 	Host        string
// 	BasePath    string
// 	Title       string
// 	Description string
// }{}

// // SwaggerDocs manages the OpenAPI documentation
// type SwaggerDocs struct {
// 	config      types.Config
// 	spec        *openapi3.T
// 	initialized bool
// }

// // NewSwaggerDocs creates a new SwaggerDocs instance
// func NewSwaggerDocs(config types.Config) *SwaggerDocs {
// 	// Set default values for Swagger info
// 	SwaggerInfo.Title = "Go Auth API"
// 	SwaggerInfo.Description = "Authentication and Authorization API"
// 	SwaggerInfo.Version = "1.0.0"
// 	SwaggerInfo.BasePath = config.BasePath
// 	SwaggerInfo.Host = config.Domain

// 	return &SwaggerDocs{
// 		config: config,
// 		spec:   createOpenAPISpec(config),
// 	}
// }

// // createOpenAPISpec creates the base OpenAPI specification
// func createOpenAPISpec(config types.Config) *openapi3.T {
// 	spec := &openapi3.T{
// 		OpenAPI: "3.0.0",
// 		Info: &openapi3.Info{
// 			Title:       SwaggerInfo.Title,
// 			Description: SwaggerInfo.Description,
// 			Version:     SwaggerInfo.Version,
// 		},
// 		Servers: openapi3.Servers{
// 			{URL: fmt.Sprintf("http://%s%s", SwaggerInfo.Host, SwaggerInfo.BasePath)},
// 		},
// 		Paths:      &openapi3.Paths{},
// 		Components: &openapi3.Components{
// 			Schemas:         openapi3.Schemas{},
// 			SecuritySchemes: openapi3.SecuritySchemes{},
// 		},
// 	}

// 	// Define common schemas
// 	spec.Components.Schemas = openapi3.Schemas{
// 		"User": &openapi3.SchemaRef{
// 			Value: &openapi3.Schema{
// 				Type: openapi3.NewObjectSchema().Type,
// 				Properties: map[string]*openapi3.SchemaRef{
// 					"id":        {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type}},
// 					"email":     {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type, Format: "email"}},
// 					"username":  {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type}},
// 					"firstName": {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type}},
// 					"lastName":  {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type}},
// 					"verified":  {Value: &openapi3.Schema{Type: openapi3.NewBoolSchema().Type}},
// 					"createdAt": {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type, Format: "date-time"}},
// 					"updatedAt": {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type, Format: "date-time"}},
// 				},
// 				Required: []string{"id", "email"},
// 			},
// 		},
// 		"Error": &openapi3.SchemaRef{
// 			Value: &openapi3.Schema{
// 				Type: openapi3.NewObjectSchema().Type,
// 				Properties: map[string]*openapi3.SchemaRef{
// 					"code":    {Value: &openapi3.Schema{Type: openapi3.NewInt64Schema().Type}},
// 					"message": {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type}},
// 				},
// 				Required: []string{"code", "message"},
// 			},
// 		},
// 	}

// 	// Define common security schemes
// 	spec.Components.SecuritySchemes = openapi3.SecuritySchemes{
// 		"BearerAuth": &openapi3.SecuritySchemeRef{
// 			Value: &openapi3.SecurityScheme{
// 				Type:         "http",
// 				Scheme:       "bearer",
// 				BearerFormat: "JWT",
// 			},
// 		},
// 		"CookieAuth": &openapi3.SecuritySchemeRef{
// 			Value: &openapi3.SecurityScheme{
// 				Type: "apiKey",
// 				In:   "cookie",
// 				Name: config.CookieName,
// 			},
// 		},
// 	}

// 	return spec
// }

// // Initialize populates the OpenAPI specification with endpoint definitions
// func (sd *SwaggerDocs) Initialize() error {
// 	if sd.initialized {
// 		return nil
// 	}

// 	// Add authentication endpoints to the spec
// 	sd.addAuthEndpoints()

// 	// For OAuth providers
// 	for _, provider := range sd.config.Providers.Enabled {
// 		sd.addOAuthEndpoints(string(provider))
// 	}

// 	sd.initialized = true
// 	return nil
// }

// // addAuthEndpoints adds the authentication endpoints to the OpenAPI spec
// func (sd *SwaggerDocs) addAuthEndpoints() {
// 	// Register endpoint
// 	sd.spec.Paths["/register"] = &openapi3.PathItem{
// 		Post: &openapi3.Operation{
// 			Tags:        []string{"Authentication"},
// 			Summary:     "Register a new user",
// 			Description: "Create a new user account with email and password",
// 			RequestBody: &openapi3.RequestBodyRef{
// 				Value: &openapi3.RequestBody{
// 					Required: true,
// 					Content: openapi3.Content{
// 						"application/json": &openapi3.MediaType{
// 							Schema: &openapi3.SchemaRef{
// 								Value: &openapi3.Schema{
// 									Type: openapi3.NewObjectSchema().Type,
// 									Properties: map[string]*openapi3.SchemaRef{
// 										"email":     {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type, Format: "email"}},
// 										"password":  {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type, Format: "password"}},
// 										"firstName": {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type}},
// 										"lastName":  {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type}},
// 									},
// 									Required: []string{"email", "password"},
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 			Responses: openapi3.Responses{
// 				"200": &openapi3.ResponseRef{
// 					Value: &openapi3.Response{
// 						Description: openapi3.NewDescription("Registration successful"),
// 						Content: openapi3.Content{
// 							"application/json": &openapi3.MediaType{
// 								Schema: &openapi3.SchemaRef{
// 									Ref: "#/components/schemas/User",
// 								},
// 							},
// 						},
// 					},
// 				},
// 				"400": &openapi3.ResponseRef{
// 					Value: &openapi3.Response{
// 						Description: openapi3.NewDescription("Invalid input"),
// 						Content: openapi3.Content{
// 							"application/json": &openapi3.MediaType{
// 								Schema: &openapi3.SchemaRef{
// 									Ref: "#/components/schemas/Error",
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}

// 	// Login endpoint
// 	sd.spec.Paths["/login"] = &openapi3.PathItem{
// 		Post: &openapi3.Operation{
// 			Tags:        []string{"Authentication"},
// 			Summary:     "User login",
// 			Description: "Login with email and password",
// 			RequestBody: &openapi3.RequestBodyRef{
// 				Value: &openapi3.RequestBody{
// 					Required: true,
// 					Content: openapi3.Content{
// 						"application/json": &openapi3.MediaType{
// 							Schema: &openapi3.SchemaRef{
// 								Value: &openapi3.Schema{
// 									Type: openapi3.NewObjectSchema().Type,
// 									Properties: map[string]*openapi3.SchemaRef{
// 										"email":    {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type, Format: "email"}},
// 										"password": {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type, Format: "password"}},
// 									},
// 									Required: []string{"email", "password"},
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 			Responses: openapi3.Responses{
// 				"200": &openapi3.ResponseRef{
// 					Value: &openapi3.Response{
// 						Description: "Login successful",
// 						Content: openapi3.Content{
// 							"application/json": &openapi3.MediaType{
// 								Schema: &openapi3.SchemaRef{
// 									Value: &openapi3.Schema{
// 										Type: openapi3.NewObjectSchema().Type,
// 										Properties: map[string]*openapi3.SchemaRef{
// 											"accessToken":  {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type}},
// 											"refreshToken": {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type}},
// 											"user":         {Ref: "#/components/schemas/User"},
// 										},
// 									},
// 								},
// 							},
// 						},
// 					},
// 				},
// 				"401": &openapi3.ResponseRef{
// 					Value: &openapi3.Response{
// 						Description: openapi3.NewDescription("Invalid credentials"),
// 						Content: openapi3.Content{
// 							"application/json": &openapi3.MediaType{
// 								Schema: &openapi3.SchemaRef{
// 									Ref: "#/components/schemas/Error",
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}

// 	// Define the rest of your endpoints in the same way...
// 	// Logout, RefreshToken, ForgotPassword, ResetPassword, etc.
// }

// // addOAuthEndpoints adds OAuth provider endpoints to the OpenAPI spec
// func (sd *SwaggerDocs) addOAuthEndpoints(provider string) {
// 	// OAuth sign-in endpoint
// 	sd.spec.Paths[fmt.Sprintf("/oauth/%s", provider)] = &openapi3.PathItem{
// 		Post: &openapi3.Operation{
// 			Tags:        []string{"OAuth"},
// 			Summary:     fmt.Sprintf("Sign in with %s", provider),
// 			Description: fmt.Sprintf("Initiate %s OAuth flow", provider),
// 			Responses: openapi3.Responses{
// 				"302": &openapi3.ResponseRef{
// 					Value: &openapi3.Response{
// 						Description: openapi3.NewDescription("Redirect to OAuth provider"),
// 					},
// 				},
// 			},
// 		},
// 	}

// 	// OAuth callback endpoint
// 	sd.spec.Paths[fmt.Sprintf("/oauth/%s/callback", provider)] = &openapi3.PathItem{
// 		Post: &openapi3.Operation{
// 			Tags:        []string{"OAuth"},
// 			Summary:     fmt.Sprintf("%s OAuth callback", provider),
// 			Description: fmt.Sprintf("Callback endpoint for %s OAuth flow", provider),
// 			Parameters: openapi3.Parameters{
// 				&openapi3.ParameterRef{
// 					Value: &openapi3.Parameter{
// 						Name:        "code",
// 						In:          "query",
// 						Description: "Authorization code from OAuth provider",
// 						Required:    true,
// 						Schema: &openapi3.SchemaRef{
// 							Value: &openapi3.Schema{
// 								Type: openapi3.NewStringSchema().Type,
// 							},
// 						},
// 					},
// 				},
// 				&openapi3.ParameterRef{
// 					Value: &openapi3.Parameter{
// 						Name:        "state",
// 						In:          "query",
// 						Description: "State parameter for CSRF protection",
// 						Required:    true,
// 						Schema: &openapi3.SchemaRef{
// 							Value: &openapi3.Schema{
// 								Type: openapi3.NewStringSchema().Type,
// 							},
// 						},
// 					},
// 				},
// 			},
// 			Responses: openapi3.Responses{
// 				"200": &openapi3.ResponseRef{
// 					Value: &openapi3.Response{
// 						Description: openapi3.NewDescription("OAuth authentication successful"),
// 						Content: openapi3.Content{
// 							"application/json": &openapi3.MediaType{
// 								Schema: &openapi3.SchemaRef{
// 									Value: &openapi3.Schema{
// 										Type: openapi3.NewObjectSchema().Type,
// 										Properties: map[string]*openapi3.SchemaRef{
// 											"accessToken":  {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type}},
// 											"refreshToken": {Value: &openapi3.Schema{Type: openapi3.NewStringSchema().Type}},
// 											"user":         {Ref: "#/components/schemas/User"},
// 										},
// 									},
// 								},
// 							},
// 						},
// 					},
// 				},
// 				"400": &openapi3.ResponseRef{
// 					Value: &openapi3.Response{
// 						Description: openapi3.NewDescription("Invalid OAuth response"),
// 						Content: openapi3.Content{
// 							"application/json": &openapi3.MediaType{
// 								Schema: &openapi3.SchemaRef{
// 									Ref: "#/components/schemas/Error",
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}
// }

// // SaveToFile saves the OpenAPI spec to a file
// func (sd *SwaggerDocs) SaveToFile(outputPath string) error {
// 	if !sd.initialized {
// 		if err := sd.Initialize(); err != nil {
// 			return err
// 		}
// 	}

// 	data, err := sd.spec.MarshalJSON()
// 	if err != nil {
// 		return fmt.Errorf("error marshaling OpenAPI spec: %w", err)
// 	}

// 	// Create directory if it doesn't exist
// 	dir := filepath.Dir(outputPath)
// 	if _, err := os.Stat(dir); os.IsNotExist(err) {
// 		if err := os.MkdirAll(dir, 0755); err != nil {
// 			return fmt.Errorf("error creating directory: %w", err)
// 		}
// 	}

// 	if err := os.WriteFile(outputPath, data, 0644); err != nil {
// 		return fmt.Errorf("error writing OpenAPI spec: %w", err)
// 	}

// 	return nil
// }

// // SetupSwaggerRoutes sets up Swagger UI routes for Gin
// func (sd *SwaggerDocs) SetupSwaggerRoutes(r *gin.Engine) {
// 	// Ensure docs are initialized
// 	if !sd.initialized {
// 		if err := sd.Initialize(); err != nil {
// 			log.Printf("Error initializing Swagger docs: %v", err)
// 			return
// 		}
// 	}

// 	// Save spec to a temporary file for swag to use
// 	tmpSpecFile := filepath.Join(os.TempDir(), "swagger.json")
// 	if err := sd.SaveToFile(tmpSpecFile); err != nil {
// 		log.Printf("Error saving Swagger spec: %v", err)
// 		return
// 	}

// 	// Set up Swagger UI routes
// 	url := ginSwagger.URL("/swagger/doc.json")
// 	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, url))

// 	// Serve the OpenAPI spec file
// 	r.GET("/swagger/doc.json", func(c *gin.Context) {
// 		c.File(tmpSpecFile)
// 	})
// }

// // SetupHttpSwaggerRoutes sets up Swagger UI routes for standard http.ServeMux
// func (sd *SwaggerDocs) SetupHttpSwaggerRoutes(mux *http.ServeMux) {
// 	// Ensure docs are initialized
// 	if !sd.initialized {
// 		if err := sd.Initialize(); err != nil {
// 			log.Printf("Error initializing Swagger docs: %v", err)
// 			return
// 		}
// 	}

// 	// Save spec to a temporary file
// 	tmpSpecFile := filepath.Join(os.TempDir(), "swagger.json")
// 	if err := sd.SaveToFile(tmpSpecFile); err != nil {
// 		log.Printf("Error saving Swagger spec: %v", err)
// 		return
// 	}

// 	// Serve the OpenAPI spec file
// 	mux.HandleFunc("/swagger/doc.json", func(w http.ResponseWriter, r *http.Request) {
// 		http.ServeFile(w, r, tmpSpecFile)
// 	})

// 	// Serve the Swagger UI
// 	mux.HandleFunc("/swagger/", func(w http.ResponseWriter, r *http.Request) {
// 		// Check if path is for Swagger UI files
// 		if strings.HasPrefix(r.URL.Path, "/swagger/") {
// 			path := strings.TrimPrefix(r.URL.Path, "/swagger/")
// 			if path == "" || path == "/" {
// 				path = "index.html"
// 			}

// 			// Serve from embedded FS
// 			file, err := swaggerUIFiles.Open(fmt.Sprintf("swagger-ui/%s", path))
// 			if err != nil {
// 				http.Error(w, "File not found", http.StatusNotFound)
// 				return
// 			}
// 			defer file.Close()

// 			// Detect content type
// 			contentType := "text/html"
// 			switch {
// 			case strings.HasSuffix(path, ".css"):
// 				contentType = "text/css"
// 			case strings.HasSuffix(path, ".js"):
// 				contentType = "application/javascript"
// 			case strings.HasSuffix(path, ".png"):
// 				contentType = "image/png"
// 			case strings.HasSuffix(path, ".svg"):
// 				contentType = "image/svg+xml"
// 			}

// 			w.Header().Set("Content-Type", contentType)
// 			http.ServeContent(w, r, path, sd.spec.Info.Version, file)
// 		}
// 	})
// }

// // Register implements swag interface to make it compatible with swaggo/swag
// type swagRegistry struct {
// 	docs *SwaggerDocs
// }

// func (s *swagRegistry) ReadDoc() string {
// 	// Ensure docs are initialized
// 	if !s.docs.initialized {
// 		if err := s.docs.Initialize(); err != nil {
// 			log.Printf("Error initializing Swagger docs: %v", err)
// 			return "{}"
// 		}
// 	}

// 	data, err := s.docs.spec.MarshalJSON()
// 	if err != nil {
// 		log.Printf("Error marshaling Swagger spec: %v", err)
// 		return "{}"
// 	}

// 	return string(data)
// }

// // RegisterSwag registers the Swagger docs with the swag package (for compatibility)
// func (sd *SwaggerDocs) RegisterSwag() {
// 	reg := &swagRegistry{docs: sd}
// 	swag.Register(swag.Name, reg)
// }
