package organizations

import (
	"errors"
	"net"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

// Handler exposes HTTP handlers for the organizations domain.
type Handler struct {
	service Service
}

// NewHandler constructs a new organizations Handler.
func NewHandler(service Service) *Handler {
	return &Handler{service: service}
}

// ApplyOrganization handles POST /api/v1/organizations.
func (h *Handler) ApplyOrganization(c *gin.Context) {
	userVal, exists := c.Get("user")
	if !exists {
		core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
		return
	}
	user, ok := userVal.(db.User)
	if !ok {
		core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "Invalid user context")
		return
	}

	var req ApplyOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid request payload format")
		return
	}

	clientIP := net.ParseIP(c.ClientIP())
	userAgent := c.Request.UserAgent()

	resp, err := h.service.ApplyOrganization(c.Request.Context(), req, user, clientIP, userAgent)
	if err != nil {
		handleError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusCreated, resp)
}

// ListMyOrganizations handles GET /api/v1/organizations/mine.
func (h *Handler) ListMyOrganizations(c *gin.Context) {
	userVal, exists := c.Get("user")
	if !exists {
		core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
		return
	}
	user, ok := userVal.(db.User)
	if !ok {
		core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "Invalid user context")
		return
	}

	resp, err := h.service.ListMyOrganizations(c.Request.Context(), user.ID)
	if err != nil {
		handleError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

// GetTenantOrganization handles GET /api/v1/organizations/:organization_id.
func (h *Handler) GetTenantOrganization(c *gin.Context) {
	orgUUID, err := parseUUIDParam(c, "organization_id")
	if err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid organization ID parameter")
		return
	}

	resp, err := h.service.GetTenantOrganization(c.Request.Context(), orgUUID)
	if err != nil {
		handleError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

// UpdateOrganizationProfile handles PATCH /api/v1/organizations/:organization_id.
func (h *Handler) UpdateOrganizationProfile(c *gin.Context) {
	orgUUID, err := parseUUIDParam(c, "organization_id")
	if err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid organization ID parameter")
		return
	}

	userVal, exists := c.Get("user")
	if !exists {
		core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
		return
	}
	user, ok := userVal.(db.User)
	if !ok {
		core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "Invalid user context")
		return
	}

	var req UpdateOrganizationProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid request payload format")
		return
	}

	clientIP := net.ParseIP(c.ClientIP())
	userAgent := c.Request.UserAgent()

	resp, err := h.service.UpdateOrganizationProfile(c.Request.Context(), orgUUID, req, user.ID, clientIP, userAgent)
	if err != nil {
		handleError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

// ListOrganizationMembers handles GET /api/v1/organizations/:organization_id/members.
func (h *Handler) ListOrganizationMembers(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	orgUUID, err := parseUUIDParam(c, "organization_id")
	if err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid organization ID parameter")
		return
	}

	roleFilter := c.Query("role")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	members, pagination, err := h.service.ListOrganizationMembers(c.Request.Context(), orgUUID, roleFilter, page, limit)
	if err != nil {
		handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"data":       members,
		"pagination": pagination,
	})
}

// ListOrganizationsAdmin handles GET /api/v1/admin/organizations.
func (h *Handler) ListOrganizationsAdmin(c *gin.Context) {
	statusFilter := c.Query("status")
	typeFilter := c.Query("type")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	orgs, pagination, err := h.service.ListOrganizationsAdmin(c.Request.Context(), statusFilter, typeFilter, page, limit)
	if err != nil {
		handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"data":       orgs,
		"pagination": pagination,
	})
}

// GetOrganizationAdminDossier handles GET /api/v1/admin/organizations/:organization_id.
func (h *Handler) GetOrganizationAdminDossier(c *gin.Context) {
	orgUUID, err := parseUUIDParam(c, "organization_id")
	if err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid organization ID parameter")
		return
	}

	resp, err := h.service.GetOrganizationAdminDossier(c.Request.Context(), orgUUID)
	if err != nil {
		handleError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

// ApproveOrganization handles POST /api/v1/admin/organizations/:organization_id/approve.
func (h *Handler) ApproveOrganization(c *gin.Context) {
	orgUUID, err := parseUUIDParam(c, "organization_id")
	if err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid organization ID parameter")
		return
	}

	reviewerVal, exists := c.Get("user")
	if !exists {
		core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
		return
	}
	reviewer, ok := reviewerVal.(db.User)
	if !ok {
		core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "Invalid user context")
		return
	}

	var req ApproveOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid request payload format")
		return
	}

	clientIP := net.ParseIP(c.ClientIP())
	userAgent := c.Request.UserAgent()

	reviewedOrg, membership, err := h.service.ApproveOrganization(c.Request.Context(), orgUUID, req, reviewer, clientIP, userAgent)
	if err != nil {
		handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"organization": reviewedOrg,
		"membership":   membership,
	})
}

// RejectOrganization handles POST /api/v1/admin/organizations/:organization_id/reject.
func (h *Handler) RejectOrganization(c *gin.Context) {
	orgUUID, err := parseUUIDParam(c, "organization_id")
	if err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid organization ID parameter")
		return
	}

	reviewerVal, exists := c.Get("user")
	if !exists {
		core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
		return
	}
	reviewer, ok := reviewerVal.(db.User)
	if !ok {
		core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "Invalid user context")
		return
	}

	var req RejectOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid request payload format")
		return
	}

	clientIP := net.ParseIP(c.ClientIP())
	userAgent := c.Request.UserAgent()

	rejectedOrg, err := h.service.RejectOrganization(c.Request.Context(), orgUUID, req, reviewer, clientIP, userAgent)
	if err != nil {
		handleError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, rejectedOrg)
}

// ListPublicVerifiedOrganizations handles GET /api/v1/public/verified-organizations.
func (h *Handler) ListPublicVerifiedOrganizations(c *gin.Context) {
	typeFilter := c.Query("type")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	orgs, pagination, err := h.service.ListPublicVerifiedOrganizations(c.Request.Context(), typeFilter, page, limit)
	if err != nil {
		handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"data":       orgs,
		"pagination": pagination,
	})
}

// GetPublicVerifiedOrganization handles GET /api/v1/public/organizations/:organization_id.
func (h *Handler) GetPublicVerifiedOrganization(c *gin.Context) {
	orgUUID, err := parseUUIDParam(c, "organization_id")
	if err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid organization ID parameter")
		return
	}

	org, err := h.service.GetPublicVerifiedOrganization(c.Request.Context(), orgUUID)
	if err != nil {
		handleError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, org)
}

func parseUUIDParam(c *gin.Context, paramName string) (pgtype.UUID, error) {
	str := c.Param(paramName)
	var u pgtype.UUID
	err := u.Scan(str)
	return u, err
}

func handleError(c *gin.Context, err error) {
	var appErr *core.AppError
	if errors.As(err, &appErr) {
		status := http.StatusBadRequest
		switch appErr.Code {
		case core.ErrCodeBadRequest, core.ErrCodeInvalidFilterParam, core.ErrCodeInvalidReasonCode, core.ErrCodeDecisionReasonRequired:
			status = http.StatusBadRequest
		case core.ErrCodeUnauthorized:
			status = http.StatusUnauthorized
		case core.ErrCodeForbidden, core.ErrCodeOrganizationNotActive, core.ErrCodeOrganizationSelfReviewProhibited:
			status = http.StatusForbidden
		case core.ErrCodeOrganizationNotFound:
			status = http.StatusNotFound
		case core.ErrCodeOrganizationAlreadyExists, core.ErrCodeOrganizationNotPending, core.ErrCodeConflict, core.ErrCodeInvalidMembershipState, core.ErrCodeInvalidMembershipRole:
			status = http.StatusConflict
		case core.ErrCodeOrganizationMembershipIntegrityViolation, core.ErrCodeInternal:
			status = http.StatusInternalServerError
		default:
			status = http.StatusBadRequest
		}
		core.SendError(c, status, appErr.Code, appErr.Message, appErr.Details)
		return
	}

	core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "An unexpected error occurred")
}
