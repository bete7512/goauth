// auth/handlers/gin_handler.go
package ginroutes

import (
	"net/http"

	"github.com/bete7512/go-auth/auth/models"
	"github.com/bete7512/go-auth/auth/schemas"
	"github.com/bete7512/go-auth/auth/types"
	"github.com/gin-gonic/gin"
)

type GinHandler struct {
	Auth *types.Auth
}

func NewGinHandler(config *types.Auth) *GinHandler {
	return &GinHandler{Auth: config}
}

func (h *GinHandler) SetupRoutes(r *gin.Engine) {
	auth := r.Group("/auth")
	{
		auth.POST("/register", h.HandleRegister)
		auth.POST("/login", h.HandleLogin)
	}
}

func (h *GinHandler) HandleRegister(c *gin.Context) {
	var req schemas.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user := models.User{
		Email:    req.Email,
		Password: req.Password,
	}

	err := h.Auth.Repository.GetUserRepository().CreateUser(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// var user models.User

	// UserPostgresRepositories := h.Auth.UserPostgresRepositories
	// depends on database implementation

	// check

	// TODO: Implement registration logic
	// user, err := h.auth.RegisterUser(req)
	// if err != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	// 	return
	// }

	// tokens, err := h.auth.GenerateAuthTokens(user.ID)
	// if err != nil {
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate tokens"})
	// 	return
	// }

	c.JSON(http.StatusCreated, gin.H{
		"user":          "user",
		"access_token":  "tokens.AccessToken",
		"refresh_token": "tokens.RefreshToken",
	})
}

func (h *GinHandler) HandleLogin(c *gin.Context) {
	var req schemas.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Implement login logic
	// user, tokens, err := h.auth.LoginUser(req)
	// if err != nil {
	// 	c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	// 	return
	// }

	c.JSON(http.StatusOK, gin.H{
		"user":          "user",
		"access_token":  "tokens.AccessToken",
		"refresh_token": "tokens.RefreshToken",
	})
}
