package ginmiddlewares

import (
	"net/http"
	"strings"

	"github.com/bete7512/go-auth/auth/types"
	"github.com/gin-gonic/gin"
)

type GinAuthMiddleware struct {
	Auth types.Auth
}

func NewGinAuthMiddleware(auth types.Auth) *GinAuthMiddleware {
	return &GinAuthMiddleware{Auth: auth}
}

func (a *GinAuthMiddleware) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header"})
			c.Abort()
			return
		}
		// TODO: do somestaffs here
		// claims, err := a.ValidateToken(parts[1])
		// if err != nil {
		// 	c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		// 	c.Abort()
		// 	return
		// }

		// c.Set("user_id", claims["user_id"])
		c.Next()
	}
}
