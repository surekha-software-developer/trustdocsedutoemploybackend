package health

import (
	"github.com/gin-gonic/gin"
)

// RegisterRoutes mounts the health and readiness routes on the router.
func RegisterRoutes(router gin.IRoutes, handler *Handler) {
	router.GET("/health", handler.Health)
	router.GET("/ready", handler.Ready)
}
