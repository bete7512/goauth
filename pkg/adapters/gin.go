
// pkg/adapters/gin.go
package adapters

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// GinAdapter wraps HTTP middleware functions for Gin framework
type GinAdapter struct{}

// NewGinAdapter creates a new Gin adapter
func NewGinAdapter() *GinAdapter {
	return &GinAdapter{}
}

// Adapt converts an HTTP middleware to Gin middleware
func (a *GinAdapter) Adapt(httpMiddleware func(http.HandlerFunc) http.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create a wrapper handler that calls gin's Next()
		wrapper := func(w http.ResponseWriter, r *http.Request) {
			// Update the gin context with the potentially modified request
			c.Request = r
			c.Next()
		}

		// Apply the HTTP middleware
		httpHandler := httpMiddleware(wrapper)
		httpHandler(c.Writer, c.Request)
	}
}

// AdminMiddleware specifically adapts the AdminMiddleware for Gin
func (a *GinAdapter) AdminMiddleware(httpAdminMiddleware func(http.HandlerFunc) http.HandlerFunc) gin.HandlerFunc {
	return a.Adapt(httpAdminMiddleware)
}

// AuthMiddleware adapts auth middleware for Gin
func (a *GinAdapter) AuthMiddleware(httpAuthMiddleware func(http.HandlerFunc) http.HandlerFunc) gin.HandlerFunc {
	return a.Adapt(httpAuthMiddleware)
}
