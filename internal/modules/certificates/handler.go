package certificates

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

// MultipartEnvelopeAllowance defines the maximum bounded overhead allowance for multipart headers and boundaries.
const MultipartEnvelopeAllowance = 64 * 1024 // 64 KB

// Handler handles HTTP requests for the certificates module.
type Handler struct {
	service *Service
}

// NewHandler constructs a new Handler.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// CreateDraft handles POST /api/v1/organizations/:organization_id/certificates
func (h *Handler) CreateDraft(c *gin.Context) {
	orgID, ok := getOrgUUID(c)
	if !ok {
		return
	}
	actorID, ok := getUserUUID(c)
	if !ok {
		return
	}

	var req CreateCertificateDraftRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid request JSON payload")
		return
	}

	resp, err := h.service.CreateDraft(c.Request.Context(), orgID, actorID, req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusCreated, resp)
}

// UpdateDraft handles PATCH /api/v1/organizations/:organization_id/certificates/:certificate_id
func (h *Handler) UpdateDraft(c *gin.Context) {
	orgID, ok := getOrgUUID(c)
	if !ok {
		return
	}
	certID, ok := getCertUUID(c)
	if !ok {
		return
	}
	actorID, ok := getUserUUID(c)
	if !ok {
		return
	}

	var req UpdateCertificateDraftRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid request JSON payload")
		return
	}

	resp, err := h.service.UpdateDraft(c.Request.Context(), certID, orgID, actorID, req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

// UploadCertificateFile handles POST /api/v1/organizations/:organization_id/certificates/:certificate_id/file
func (h *Handler) UploadCertificateFile(c *gin.Context) {
	orgID, ok := getOrgUUID(c)
	if !ok {
		return
	}
	certID, ok := getCertUUID(c)
	if !ok {
		return
	}
	actorID, ok := getUserUUID(c)
	if !ok {
		return
	}

	// 1. Bound request body size at handler boundary using http.MaxBytesReader
	// Permits configured file maximum plus an explicit, bounded multipart-envelope allowance.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, h.service.maxFileSize+MultipartEnvelopeAllowance)

	// 2. Parse multipart form
	fileHeader, err := c.FormFile("file")
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) || strings.Contains(err.Error(), "request body too large") {
			core.SendError(c, http.StatusRequestEntityTooLarge, core.ErrCodeFileTooLarge, "Request payload exceeds maximum allowed size")
			return
		}
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Multipart file 'file' is required")
		return
	}

	// 3. Enforce bounded non-file multipart field data limit
	if c.Request.MultipartForm != nil {
		var nonFileBytes int64
		for k, vals := range c.Request.MultipartForm.Value {
			nonFileBytes += int64(len(k))
			for _, v := range vals {
				nonFileBytes += int64(len(v))
			}
		}
		for fieldName, headers := range c.Request.MultipartForm.File {
			if fieldName != "file" {
				for _, fh := range headers {
					nonFileBytes += fh.Size
				}
			}
		}
		if nonFileBytes > MultipartEnvelopeAllowance {
			core.SendError(c, http.StatusRequestEntityTooLarge, core.ErrCodeFileTooLarge, "Non-file multipart fields exceed envelope allowance")
			return
		}
	}

	file, err := fileHeader.Open()
	if err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Failed to open uploaded file")
		return
	}
	defer file.Close()

	resp, err := h.service.UploadCertificateFile(
		c.Request.Context(),
		certID, orgID, actorID,
		fileHeader.Filename,
		file,
		fileHeader.Size,
		fileHeader.Header.Get("Content-Type"),
	)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

// IssueCertificate handles POST /api/v1/organizations/:organization_id/certificates/:certificate_id/issue
func (h *Handler) IssueCertificate(c *gin.Context) {
	orgID, ok := getOrgUUID(c)
	if !ok {
		return
	}
	certID, ok := getCertUUID(c)
	if !ok {
		return
	}
	actorID, ok := getUserUUID(c)
	if !ok {
		return
	}

	resp, err := h.service.IssueCertificate(c.Request.Context(), certID, orgID, actorID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

// RevokeCertificate handles POST /api/v1/organizations/:organization_id/certificates/:certificate_id/revoke
func (h *Handler) RevokeCertificate(c *gin.Context) {
	orgID, ok := getOrgUUID(c)
	if !ok {
		return
	}
	certID, ok := getCertUUID(c)
	if !ok {
		return
	}
	actorID, ok := getUserUUID(c)
	if !ok {
		return
	}

	var req RevokeCertificateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid request JSON payload")
		return
	}

	resp, err := h.service.RevokeCertificate(c.Request.Context(), certID, orgID, actorID, req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

// ReplaceCertificate handles POST /api/v1/organizations/:organization_id/certificates/:certificate_id/replace
func (h *Handler) ReplaceCertificate(c *gin.Context) {
	orgID, ok := getOrgUUID(c)
	if !ok {
		return
	}
	certID, ok := getCertUUID(c)
	if !ok {
		return
	}
	actorID, ok := getUserUUID(c)
	if !ok {
		return
	}

	var req ReplaceCertificateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid request JSON payload")
		return
	}

	oldResp, newResp, err := h.service.ReplaceCertificate(c.Request.Context(), certID, orgID, actorID, req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, map[string]interface{}{
		"original":    oldResp,
		"replacement": newResp,
	})
}

// DeleteDraft handles DELETE /api/v1/organizations/:organization_id/certificates/:certificate_id
func (h *Handler) DeleteDraft(c *gin.Context) {
	orgID, ok := getOrgUUID(c)
	if !ok {
		return
	}
	certID, ok := getCertUUID(c)
	if !ok {
		return
	}
	actorID, ok := getUserUUID(c)
	if !ok {
		return
	}

	err := h.service.DeleteDraft(c.Request.Context(), certID, orgID, actorID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, map[string]string{
		"message": "Certificate draft successfully deleted",
	})
}

// GetCertificate handles GET /api/v1/organizations/:organization_id/certificates/:certificate_id
func (h *Handler) GetCertificate(c *gin.Context) {
	orgID, ok := getOrgUUID(c)
	if !ok {
		return
	}
	certID, ok := getCertUUID(c)
	if !ok {
		return
	}

	resp, err := h.service.GetCertificate(c.Request.Context(), certID, orgID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

// ListCertificates handles GET /api/v1/organizations/:organization_id/certificates
func (h *Handler) ListCertificates(c *gin.Context) {
	orgID, ok := getOrgUUID(c)
	if !ok {
		return
	}

	var status, email *string
	if s := strings.TrimSpace(c.Query("status")); s != "" {
		status = &s
	}
	if e := strings.TrimSpace(c.Query("recipient_email")); e != "" {
		email = &e
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	certs, pagination, err := h.service.ListCertificates(c.Request.Context(), orgID, status, email, page, limit)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, map[string]interface{}{
		"certificates": certs,
		"pagination":   pagination,
	})
}

// ListMyCertificates handles GET /api/v1/certificates/mine
func (h *Handler) ListMyCertificates(c *gin.Context) {
	studentID, ok := getUserUUID(c)
	if !ok {
		return
	}

	var status *string
	if s := strings.TrimSpace(c.Query("status")); s != "" {
		status = &s
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	certs, pagination, err := h.service.ListStudentCertificates(c.Request.Context(), studentID, status, page, limit)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, map[string]interface{}{
		"certificates": certs,
		"pagination":   pagination,
	})
}

// GetMyCertificate handles GET /api/v1/certificates/mine/:certificate_id
func (h *Handler) GetMyCertificate(c *gin.Context) {
	studentID, ok := getUserUUID(c)
	if !ok {
		return
	}
	certID, ok := getCertUUID(c)
	if !ok {
		return
	}

	resp, err := h.service.GetStudentCertificate(c.Request.Context(), certID, studentID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

// DownloadCertificate handles GET /api/v1/certificates/:certificate_id/download
func (h *Handler) DownloadCertificate(c *gin.Context) {
	certID, ok := getCertUUID(c)
	if !ok {
		return
	}
	actorID, ok := getUserUUID(c)
	if !ok {
		return
	}

	// Check if the user is acting as an issuer member via optional query / context
	isIssuer := false
	var orgID *pgtype.UUID

	orgIDStr := c.Query("organization_id")
	if orgIDStr != "" {
		u := StringToUUID(orgIDStr)
		if u.Valid {
			orgID = &u
			isIssuer = true
		}
	}

	res, err := h.service.DownloadCertificate(c.Request.Context(), certID, actorID, isIssuer, orgID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	// Apply returned headers
	for k, v := range res.Headers {
		c.Header(k, v)
	}

	// Check if download is denied with status metadata (student attempting to download REVOKED or REPLACED)
	if res.DeniedResponse != nil {
		c.JSON(http.StatusGone, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "CERTIFICATE_" + res.Status,
				"message": res.DeniedResponse.Message,
				"details": res.DeniedResponse,
			},
		})
		return
	}

	core.SendSuccess(c, http.StatusOK, map[string]string{
		"download_url": res.PresignedURL,
		"file_name":    res.FileName,
	})
}

// VerifyPublicCertificate handles GET /api/v1/public/certificates/:public_id
func (h *Handler) VerifyPublicCertificate(c *gin.Context) {
	publicID := c.Param("public_id")
	resp, err := h.service.VerifyPublicCertificate(c.Request.Context(), publicID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	core.SendSuccess(c, http.StatusOK, resp)
}

func getOrgUUID(c *gin.Context) (pgtype.UUID, bool) {
	param := c.Param("organization_id")
	u := StringToUUID(param)
	if !u.Valid {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid organization ID parameter")
		return pgtype.UUID{}, false
	}
	return u, true
}

func getCertUUID(c *gin.Context) (pgtype.UUID, bool) {
	param := c.Param("certificate_id")
	u := StringToUUID(param)
	if !u.Valid {
		core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid certificate ID parameter")
		return pgtype.UUID{}, false
	}
	return u, true
}

func getUserUUID(c *gin.Context) (pgtype.UUID, bool) {
	userVal, exists := c.Get("user")
	if !exists {
		core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
		return pgtype.UUID{}, false
	}
	user, ok := userVal.(db.User)
	if !ok {
		core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "Invalid user context")
		return pgtype.UUID{}, false
	}
	return user.ID, true
}

func handleServiceError(c *gin.Context, err error) {
	var appErr *core.AppError
	if errors.As(err, &appErr) {
		status := http.StatusBadRequest
		switch appErr.Code {
		case core.ErrCodeCertificateNotFound, core.ErrCodeRecipientNotFound:
			status = http.StatusNotFound
		case core.ErrCodeForbidden:
			status = http.StatusForbidden
		case core.ErrCodeFileTooLarge:
			status = http.StatusRequestEntityTooLarge
		case core.ErrCodeCertificateRevoked, core.ErrCodeCertificateReplaced:
			status = http.StatusGone
		case core.ErrCodeConflict, core.ErrCodeDuplicateDocumentHash, core.ErrCodeCertificateAlreadyIssued, core.ErrCodeCertificateStateConflict:
			status = http.StatusConflict
		case core.ErrCodeInternal:
			status = http.StatusInternalServerError
		}
		core.SendError(c, status, appErr.Code, appErr.Message)
		return
	}

	core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "An unexpected error occurred")
}
