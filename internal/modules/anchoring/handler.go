package anchoring

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

// Handler exposes HTTP routes for proof verification and Merkle batch management.
type Handler struct {
	service *Service
	logger  *slog.Logger
}

// NewHandler constructs an anchoring Handler.
func NewHandler(service *Service, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		service: service,
		logger:  logger,
	}
}

// VerifyProof handles POST /api/v1/public/certificates/verify-proof
func (h *Handler) VerifyProof(c *gin.Context) {
	c.Header("Cache-Control", "no-store")

	var req VerifyProofRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid request JSON payload")
		return
	}

	resp, err := h.service.VerifyProof(c.Request.Context(), req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

// CreateBatch handles POST /api/v1/admin/anchoring/batches (admin manual trigger)
func (h *Handler) CreateBatch(c *gin.Context) {
	var req CreateBatchRequest
	_ = c.ShouldBindJSON(&req)

	resp, err := h.service.CreateBatch(c.Request.Context(), req.BatchSize)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusCreated, resp)
}

// GetBatch handles GET /api/v1/admin/anchoring/batches/:id
func (h *Handler) GetBatch(c *gin.Context) {
	id := c.Param("id")
	resp, err := h.service.GetBatch(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

// ListBatches handles GET /api/v1/admin/anchoring/batches
func (h *Handler) ListBatches(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "20")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	resp, err := h.service.ListBatches(c.Request.Context(), int32(limit), int32(offset))
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

func handleServiceError(c *gin.Context, err error) {
	var appErr *core.AppError
	if errors.As(err, &appErr) {
		status := http.StatusBadRequest
		switch appErr.Code {
		case core.ErrCodeBatchNotFound:
			status = http.StatusNotFound
		case core.ErrCodeProofDepthExceeded:
			status = http.StatusBadRequest
		case core.ErrCodeForbidden:
			status = http.StatusForbidden
		case core.ErrCodeConflict, core.ErrCodeBatchAlreadyAnchored:
			status = http.StatusConflict
		case core.ErrCodeInternal, core.ErrCodeBlockchainUnavailable:
			status = http.StatusInternalServerError
		}
		core.SendError(c, status, appErr.Code, appErr.Message)
		return
	}

	core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "An unexpected error occurred")
}
