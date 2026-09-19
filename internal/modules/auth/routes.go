package auth

import (
	"github.com/gin-gonic/gin"
)

// RegisterRoutes sets up all authentication endpoints under the provided router group.
func RegisterRoutes(
	rg *gin.RouterGroup,
	handler *Handler,
	originMiddleware gin.HandlerFunc,
	jsonMiddleware gin.HandlerFunc,
	rateLimitRegisterMiddleware gin.HandlerFunc,
	rateLimitLoginMiddleware gin.HandlerFunc,
	authMiddleware gin.HandlerFunc,
	csrfValidationMiddleware gin.HandlerFunc,
) {
	authGroup := rg.Group("/auth")
	{
		authGroup.POST("/register", originMiddleware, jsonMiddleware, rateLimitRegisterMiddleware, handler.Register)
		authGroup.POST("/login", originMiddleware, jsonMiddleware, rateLimitLoginMiddleware, handler.Login)
		authGroup.GET("/csrf", handler.CSRF)
		authGroup.POST("/logout", originMiddleware, csrfValidationMiddleware, handler.Logout)
		authGroup.GET("/me", authMiddleware, handler.Me)
	}
}
