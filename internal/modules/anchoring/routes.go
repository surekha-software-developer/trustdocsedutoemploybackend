package anchoring

import "github.com/gin-gonic/gin"

// RegisterRoutes registers the public proof verification route and admin batch routes.
func RegisterRoutes(
	v1 *gin.RouterGroup,
	handler *Handler,
	originMw gin.HandlerFunc,
	jsonMw gin.HandlerFunc,
	authMw gin.HandlerFunc,
	csrfMw gin.HandlerFunc,
	rateLimitPublic gin.HandlerFunc,
) {
	// Public proof-verification API: bounded, unauthenticated, rate-limited
	v1.POST("/public/certificates/verify-proof", rateLimitPublic, jsonMw, handler.VerifyProof)

	// Admin batch management routes
	if authMw != nil {
		admin := v1.Group("/admin/anchoring", authMw)
		if csrfMw != nil {
			admin.Use(csrfMw)
		}
		if originMw != nil {
			admin.Use(originMw)
		}

		admin.POST("/batches", jsonMw, handler.CreateBatch)
		admin.GET("/batches", handler.ListBatches)
		admin.GET("/batches/:id", handler.GetBatch)
	}
}
