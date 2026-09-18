package health

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

// Handler exposes HTTP handlers for health and readiness endpoints.
type Handler struct {
	service Service
}

// NewHandler constructs a new health Handler.
func NewHandler(service Service) *Handler {
	return &Handler{service: service}
}

// Health handles GET /health requests.
func (h *Handler) Health(c *gin.Context) {
	data := h.service.CheckHealth()
	core.SendSuccess(c, http.StatusOK, data)
}

// Ready handles GET /ready requests.
func (h *Handler) Ready(c *gin.Context) {
	data := h.service.CheckReady()
	core.SendSuccess(c, http.StatusOK, data)
}
