package docs

import (
	"encoding/json"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	swaggerJSONPath = "swagger.json"
	indexHTML       = "index.html"
)

// SwaggerHTML is the template for the Swagger UI HTML page
const SwaggerHTML = `
					<!DOCTYPE html>
					<html lang="en">
					<head>
					    <meta charset="UTF-8">
					    <title>%s</title>
					    <link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.18.3/swagger-ui.css" />
					    <style>
					        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
					        *, *:before, *:after { box-sizing: inherit; }
					        body { margin: 0; background: #fafafa; }
					    </style>
					</head>
					<body>
					    <div id="swagger-ui"></div>
					    <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.18.3/swagger-ui-bundle.js"></script>
					    <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.18.3/swagger-ui-standalone-preset.js"></script>
					    <script>
					    window.onload = function() {
					        const ui = SwaggerUIBundle({
					            url: "%s",
					            dom_id: '#swagger-ui',
					            deepLinking: true,
					            presets: [
					                SwaggerUIBundle.presets.apis,
					                SwaggerUIStandalonePreset
					            ],
					            plugins: [
					                SwaggerUIBundle.plugins.DownloadUrl
					            ],
					            layout: "StandaloneLayout"
					        });
					        window.ui = ui;
					    };
					    </script>
					</body>
					</html>
					`

// SwaggerHandler is the HTTP handler for serving Swagger documentation
type SwaggerHandler struct {
	SwaggerInfo
}

// NewSwaggerHandler creates a new SwaggerHandler
func NewSwaggerHandler(info SwaggerInfo) *SwaggerHandler {

	if info.BasePath == "" {
		info.BasePath = "/"
	}
	if info.DocPath == "" {
		info.DocPath = "/docs"
	}
	return &SwaggerHandler{
		SwaggerInfo: SwaggerInfo{
			Title:       info.Title,
			BasePath:    info.BasePath,
			Version:     info.Version,
			Host:        info.Host,
			DocPath:     info.DocPath,
			Description: info.Description,
			Schemes:     info.Schemes,
		},
	}
}

// setCORSHeaders sets CORS headers for browser compatibility
func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, api_key, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, OPTIONS")
}

// ServeHTTP implements the http.Handler interface
func (h *SwaggerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	setCORSHeaders(w)

	// Handle OPTIONS request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	// Parse the URL path
	urlPath := r.URL.Path
	// Check if the request is for the Swagger JSON
	if strings.HasSuffix(urlPath, swaggerJSONPath) {
		h.serveSwaggerJSON(w, r)
		return
	}
	// Check if the request is for the Swagger UI
	if strings.HasSuffix(urlPath, "/") || strings.HasSuffix(urlPath, h.DocPath) || strings.HasSuffix(urlPath, h.DocPath+"/") {
		h.serveSwaggerUI(w, r)
		return
	}

	// If the path doesn't match, return 404
	http.NotFound(w, r)
}

// serveSwaggerJSON serves the Swagger JSON specification
func (h *SwaggerHandler) serveSwaggerJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get the Swagger documentation
	swaggerSpec := SwaggerDoc(h.SwaggerInfo)

	// Marshal to JSON with indentation for readability
	jsonData, err := json.MarshalIndent(swaggerSpec, "", "  ")
	if err != nil {
		http.Error(w, "Failed to generate Swagger JSON", http.StatusInternalServerError)
		return
	}

	w.Write(jsonData)
}

// serveSwaggerUI serves the Swagger UI HTML page
func (h *SwaggerHandler) serveSwaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	// Format the swagger JSON URL
	jsonURL := path.Join(h.BasePath, swaggerJSONPath)
	if !strings.HasPrefix(jsonURL, "/") {
		jsonURL = "/" + jsonURL
	}

	// Generate the HTML with the correct title and JSON URL
	html := strings.Replace(SwaggerHTML, "%s", h.Title, 1)
	html = strings.Replace(html, "%s", jsonURL, 1)

	w.Write([]byte(html))
}

// RegisterRoutes registers Swagger documentation routes for standard net/http
func RegisterRoutes(mux *http.ServeMux, info SwaggerInfo) {
	handler := NewSwaggerHandler(info)

	// Register the handler for various paths
	basePath := strings.TrimSuffix(info.BasePath, "/")
	docPath := info.DocPath

	// Main documentation paths
	mux.Handle(path.Join(basePath, docPath)+"/", handler)
	mux.Handle(path.Join(basePath, docPath), handler)

	// Root paths
	if basePath != "" {
		mux.Handle(basePath+"/", handler)
		mux.Handle(basePath, handler)
	}

	// JSON specification path
	mux.Handle(path.Join(basePath, swaggerJSONPath), handler)
}

// RegisterGinRoutes registers Swagger documentation routes for Gin
func RegisterGinRoutes(r *gin.Engine, info SwaggerInfo) {
	handler := NewSwaggerHandler(info)

	// Register the handler for various paths
	basePath := strings.TrimSuffix(info.BasePath, "/")
	docPath := info.DocPath
	// Main documentation paths
	r.GET(path.Join(basePath, docPath), gin.WrapH(handler))
	r.GET(path.Join(basePath, docPath)+"/", gin.WrapH(handler))

	// Root paths
	if basePath != "" {
		r.GET(basePath, gin.WrapH(handler))
		r.GET(basePath+"/", gin.WrapH(handler))
	}

	// JSON specification path
	r.GET(path.Join(basePath, swaggerJSONPath), gin.WrapH(handler))

	// Handle OPTIONS requests for CORS
	r.OPTIONS(path.Join(basePath, docPath), gin.WrapH(handler))
	r.OPTIONS(path.Join(basePath, docPath)+"/", gin.WrapH(handler))
	r.OPTIONS(path.Join(basePath, swaggerJSONPath), gin.WrapH(handler))
}
