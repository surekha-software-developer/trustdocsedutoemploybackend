package certificates

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/storage"
)

// Sleeper defines sleep abstraction to enable deterministic zero-delay retry testing.
type Sleeper func(d time.Duration)

var docHashRegex = regexp.MustCompile("^[0-9a-f]{64}$")

// BuildCertificateStorageKey constructs the canonical object storage key for a certificate PDF:
// certificates/{organization_id}/{certificate_id}/{document_hash}.pdf
// It strictly validates UUIDs and requires a lowercase 64-character SHA-256 hex string.
// No recipient PII or original filename appears in the storage key.
func BuildCertificateStorageKey(orgID, certID pgtype.UUID, docHash string) (string, error) {
	orgStr := UUIDToString(orgID)
	if !orgID.Valid || orgStr == "" {
		return "", fmt.Errorf("invalid organization UUID")
	}
	certStr := UUIDToString(certID)
	if !certID.Valid || certStr == "" {
		return "", fmt.Errorf("invalid certificate UUID")
	}
	cleanHash := strings.TrimSpace(docHash)
	if !docHashRegex.MatchString(cleanHash) {
		return "", fmt.Errorf("invalid document hash: must be lowercase 64-character SHA-256 hex string")
	}
	return fmt.Sprintf("certificates/%s/%s/%s.pdf", orgStr, certStr, cleanHash), nil
}

// DownloadResult represents output from the download authorization decision.
type DownloadResult struct {
	PresignedURL   string
	FileName       string
	Status         string
	DeniedResponse *CertificateStatusMetadataResponse
	Headers        map[string]string
}

// AnchoringMetadataProvider defines the interface for retrieving blockchain anchoring metadata.
type AnchoringMetadataProvider interface {
	GetCertificateAnchoring(ctx context.Context, publicID string) (*CertificateAnchoringMetadata, error)
}

// Service defines domain logic operations for certificates.
type Service struct {
	repo              Repository
	storage           storage.ObjectStorage
	logger            *slog.Logger
	maxFileSize       int64
	presignTTL        time.Duration
	sleeper           Sleeper
	nowFunc           func() time.Time
	anchoringProvider AnchoringMetadataProvider
}

// NewService constructs a new certificate Service.
func NewService(repo Repository, stor storage.ObjectStorage, maxFileSize int64, presignTTL time.Duration, logger *slog.Logger) *Service {
	if maxFileSize <= 0 || maxFileSize > 10485760 {
		maxFileSize = 10485760
	}
	if presignTTL <= 0 || presignTTL > storage.MaxPresignTTL {
		presignTTL = storage.MaxPresignTTL
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		repo:        repo,
		storage:     stor,
		logger:      logger,
		maxFileSize: maxFileSize,
		presignTTL:  presignTTL,
		sleeper:     time.Sleep,
		nowFunc:     func() time.Time { return time.Now().UTC() },
	}
}

// SetAnchoringProvider injects an optional anchoring metadata provider.
func (s *Service) SetAnchoringProvider(p AnchoringMetadataProvider) {
	s.anchoringProvider = p
}

// SetSleeper overrides time.Sleep for testing.
func (s *Service) SetSleeper(sl Sleeper) {
	s.sleeper = sl
}

// SetNowFunc overrides the current time provider for testing.
func (s *Service) SetNowFunc(fn func() time.Time) {
	s.nowFunc = fn
}

func (s *Service) now() time.Time {
	if s.nowFunc != nil {
		return s.nowFunc()
	}
	return time.Now().UTC()
}

// CreateDraft creates a new unissued certificate draft.
func (s *Service) CreateDraft(ctx context.Context, orgID, actorUserID pgtype.UUID, req CreateCertificateDraftRequest) (CertificateResponse, error) {
	if err := req.ValidateAndCanonicalize(); err != nil {
		return CertificateResponse{}, err
	}
	if err := req.ValidateFutureIssueDate(s.now()); err != nil {
		return CertificateResponse{}, err
	}

	recipientUUID := StringToUUID(req.RecipientUserID)
	if !recipientUUID.Valid {
		return CertificateResponse{}, core.NewAppError(core.ErrCodeBadRequest, "Invalid recipient_user_id UUID format")
	}

	gradDate, _ := time.Parse("2006-01-02", req.GraduationDate)
	issueDate, _ := time.Parse("2006-01-02", req.IssueDate)

	publicID, err := generatePublicID()
	if err != nil {
		return CertificateResponse{}, fmt.Errorf("failed to generate public ID: %w", err)
	}

	params := db.CreateCertificateDraftParams{
		PublicID:        publicID,
		OrganizationID:  orgID,
		RecipientUserID: recipientUUID,
		RecipientName:   req.RecipientName,
		RecipientEmail:  req.RecipientEmail,
		Title:           req.Title,
		DegreeType:      req.DegreeType,
		GraduationDate:  pgtype.Date{Time: gradDate, Valid: true},
		IssueDate:       pgtype.Date{Time: issueDate, Valid: true},
		CreatedByUserID: actorUserID,
	}

	if req.StudentIDNumber != nil {
		params.StudentIDNumber = pgtype.Text{String: *req.StudentIDNumber, Valid: true}
	}
	if req.Major != nil {
		params.Major = pgtype.Text{String: *req.Major, Valid: true}
	}
	if req.GradeOrHonors != nil {
		params.GradeOrHonors = pgtype.Text{String: *req.GradeOrHonors, Valid: true}
	}

	auditPayload, _ := BuildSanitizedAuditPayload(pgtype.UUID{}, orgID, publicID, "DRAFT", nil, nil, nil)
	auditParams := db.CreateAuditLogParams{
		ActorUserID:          actorUserID,
		TargetOrganizationID: orgID,
		Action:               "CERTIFICATE_DRAFT_CREATED",
		ResourceType:         "CERTIFICATE",
		Payload:              auditPayload,
	}

	cert, err := s.repo.CreateDraftTx(ctx, params, auditParams)
	if err != nil {
		return CertificateResponse{}, err
	}

	return toCertificateResponse(cert), nil
}

// UpdateDraft updates an unissued certificate draft.
func (s *Service) UpdateDraft(ctx context.Context, certID, orgID, actorUserID pgtype.UUID, req UpdateCertificateDraftRequest) (CertificateResponse, error) {
	if err := req.ValidateAndCanonicalize(); err != nil {
		return CertificateResponse{}, err
	}
	if err := req.ValidateFutureIssueDate(s.now()); err != nil {
		return CertificateResponse{}, err
	}

	params := db.UpdateCertificateDraftParams{
		ID:             certID,
		OrganizationID: orgID,
	}

	if req.RecipientUserID != nil {
		u := StringToUUID(*req.RecipientUserID)
		if !u.Valid {
			return CertificateResponse{}, core.NewAppError(core.ErrCodeBadRequest, "Invalid recipient_user_id UUID format")
		}
		params.RecipientUserID = u
	}
	if req.RecipientName != nil {
		params.RecipientName = pgtype.Text{String: *req.RecipientName, Valid: true}
	}
	if req.RecipientEmail != nil {
		params.RecipientEmail = pgtype.Text{String: *req.RecipientEmail, Valid: true}
	}
	if req.StudentIDNumber != nil {
		params.StudentIDNumber = pgtype.Text{String: *req.StudentIDNumber, Valid: true}
	}
	if req.Title != nil {
		params.Title = pgtype.Text{String: *req.Title, Valid: true}
	}
	if req.DegreeType != nil {
		params.DegreeType = pgtype.Text{String: *req.DegreeType, Valid: true}
	}
	if req.Major != nil {
		params.Major = pgtype.Text{String: *req.Major, Valid: true}
	}
	if req.GradeOrHonors != nil {
		params.GradeOrHonors = pgtype.Text{String: *req.GradeOrHonors, Valid: true}
	}
	if req.GraduationDate != nil {
		t, _ := time.Parse("2006-01-02", *req.GraduationDate)
		params.GraduationDate = pgtype.Date{Time: t, Valid: true}
	}
	if req.IssueDate != nil {
		t, _ := time.Parse("2006-01-02", *req.IssueDate)
		params.IssueDate = pgtype.Date{Time: t, Valid: true}
	}

	auditPayload, _ := BuildSanitizedAuditPayload(certID, orgID, "", "DRAFT", nil, nil, nil)
	auditParams := db.CreateAuditLogParams{
		ActorUserID:          actorUserID,
		TargetOrganizationID: orgID,
		Action:               "CERTIFICATE_DRAFT_UPDATED",
		ResourceType:         "CERTIFICATE",
		Payload:              auditPayload,
	}

	cert, err := s.repo.UpdateDraftTx(ctx, params, auditParams)
	if err != nil {
		return CertificateResponse{}, err
	}

	return toCertificateResponse(cert), nil
}

// UploadCertificateFile processes, validates, hashes, and stores a certificate PDF document.
func (s *Service) UploadCertificateFile(
	ctx context.Context,
	certID, orgID, actorUserID pgtype.UUID,
	fileName string,
	body io.Reader,
	declaredSize int64,
	contentType string,
) (CertificateResponse, error) {
	// 1. Validate certificate draft state before processing upload
	cert, err := s.repo.GetCertificateByID(ctx, certID, orgID)
	if err != nil {
		return CertificateResponse{}, err
	}
	if cert.Status != "DRAFT" {
		return CertificateResponse{}, core.NewAppError(core.ErrCodeCertificateNotDraft, "Files can only be attached to DRAFT certificates")
	}

	// 2. Validate declared file size and body
	if body == nil || declaredSize == 0 {
		return CertificateResponse{}, core.NewAppError(core.ErrCodeBadRequest, "Uploaded file cannot be empty")
	}
	if declaredSize > s.maxFileSize {
		return CertificateResponse{}, core.NewAppError(core.ErrCodeFileTooLarge, fmt.Sprintf("File size exceeds maximum allowed size of %d bytes", s.maxFileSize))
	}

	// 3. Read bounded input using LimitedReader (maxSize + 1 to detect overflow)
	lr := &io.LimitedReader{
		R: body,
		N: s.maxFileSize + 1,
	}

	var buf bytes.Buffer
	hasher := sha256.New()
	multiWriter := io.MultiWriter(&buf, hasher)

	n, err := io.Copy(multiWriter, lr)
	if err != nil {
		return CertificateResponse{}, core.NewAppError(core.ErrCodeBadRequest, "Failed to read uploaded file payload")
	}
	if n == 0 {
		return CertificateResponse{}, core.NewAppError(core.ErrCodeBadRequest, "Uploaded file cannot be empty")
	}
	if n > s.maxFileSize {
		return CertificateResponse{}, core.NewAppError(core.ErrCodeFileTooLarge, fmt.Sprintf("File size exceeds maximum allowed size of %d bytes", s.maxFileSize))
	}

	fileBytes := buf.Bytes()

	// 4. Magic byte inspection: First five exact bytes must be "%PDF-"
	if len(fileBytes) < 5 || string(fileBytes[:5]) != "%PDF-" {
		return CertificateResponse{}, core.NewAppError(core.ErrCodeInvalidFileFormat, "File is not a valid PDF document (must start with %PDF-)")
	}

	// 5. Compute cryptographic SHA-256 hash in lowercase hex
	hashBytes := hasher.Sum(nil)
	docHash := hex.EncodeToString(hashBytes)

	// 6. Sanitize filename
	cleanFileName := filepath.Base(strings.TrimSpace(fileName))
	if cleanFileName == "" || cleanFileName == "." || cleanFileName == "/" {
		cleanFileName = "certificate.pdf"
	}
	if !strings.HasSuffix(strings.ToLower(cleanFileName), ".pdf") {
		cleanFileName += ".pdf"
	}

	// 7. Check document hash conflict against finalized certificates
	conflict, err := s.repo.CheckDocumentHashConflict(ctx, docHash)
	if err != nil {
		return CertificateResponse{}, err
	}
	if conflict {
		return CertificateResponse{}, core.NewAppError(core.ErrCodeDuplicateDocumentHash, "A certificate with this exact document hash has already been finalized")
	}

	// 8. Construct canonical object key: certificates/{org_id}/{cert_id}/{hash}.pdf
	storageKey, err := BuildCertificateStorageKey(orgID, certID, docHash)
	if err != nil {
		return CertificateResponse{}, core.NewAppError(core.ErrCodeBadRequest, err.Error())
	}

	// 9. Upload new object to storage
	err = s.storage.PutObject(ctx, storageKey, bytes.NewReader(fileBytes), int64(len(fileBytes)), "application/pdf")
	if err != nil {
		return CertificateResponse{}, core.NewAppError(core.ErrCodeInternal, "Failed to store document in object storage")
	}

	// 10. Attach metadata in database transaction
	attachParams := db.AttachCertificateFileParams{
		ID:             certID,
		OrganizationID: orgID,
		FileStorageKey: pgtype.Text{String: storageKey, Valid: true},
		FileName:       pgtype.Text{String: cleanFileName, Valid: true},
		FileSize:       pgtype.Int8{Int64: int64(len(fileBytes)), Valid: true},
		FileMimeType:   pgtype.Text{String: "application/pdf", Valid: true},
		DocumentHash:   pgtype.Text{String: docHash, Valid: true},
	}

	auditPayload, _ := BuildSanitizedAuditPayload(certID, orgID, cert.PublicID, "DRAFT", nil, nil, nil)
	auditParams := db.CreateAuditLogParams{
		ActorUserID:          actorUserID,
		TargetOrganizationID: orgID,
		Action:               "CERTIFICATE_FILE_UPLOADED",
		ResourceType:         "CERTIFICATE",
		Payload:              auditPayload,
	}

	updatedCert, err := s.repo.AttachFileTx(ctx, attachParams, auditParams)
	if err != nil {
		// Compensation: delete newly uploaded object since DB transaction failed
		s.compensateNewUpload(storageKey, certID, orgID)
		return CertificateResponse{}, err
	}

	// 11. Post-commit cleanup: if this draft had a previous different storage key, delete it synchronously
	// Using a bounded dedicated service context; failure never rolls back the committed DB operation.
	if cert.FileStorageKey.Valid && cert.FileStorageKey.String != "" && cert.FileStorageKey.String != storageKey {
		s.cleanupStorageObjectWithRetry(cert.FileStorageKey.String, certID, orgID)
	}

	return toCertificateResponse(updatedCert), nil
}

// IssueCertificate finalizes and issues an eligible certificate draft.
func (s *Service) IssueCertificate(ctx context.Context, certID, orgID, actorUserID pgtype.UUID) (CertificateResponse, error) {
	auditPayload, _ := BuildSanitizedAuditPayload(certID, orgID, "", "ISSUED", nil, nil, nil)
	auditParams := db.CreateAuditLogParams{
		ActorUserID:          actorUserID,
		TargetOrganizationID: orgID,
		Action:               "CERTIFICATE_ISSUED",
		ResourceType:         "CERTIFICATE",
		Payload:              auditPayload,
	}

	cert, err := s.repo.IssueCertificateTx(ctx, certID, orgID, actorUserID, auditParams)
	if err != nil {
		return CertificateResponse{}, err
	}

	return toCertificateResponse(cert), nil
}

// RevokeCertificate revokes an issued certificate.
func (s *Service) RevokeCertificate(ctx context.Context, certID, orgID, actorUserID pgtype.UUID, req RevokeCertificateRequest) (CertificateResponse, error) {
	if err := req.Validate(); err != nil {
		return CertificateResponse{}, err
	}

	auditPayload, _ := BuildSanitizedAuditPayload(certID, orgID, "", "REVOKED", &req.ReasonCode, nil, nil)
	auditParams := db.CreateAuditLogParams{
		ActorUserID:          actorUserID,
		TargetOrganizationID: orgID,
		Action:               "CERTIFICATE_REVOKED",
		ResourceType:         "CERTIFICATE",
		Payload:              auditPayload,
	}

	cert, err := s.repo.RevokeCertificateTx(ctx, certID, orgID, actorUserID, req.ReasonCode, req.Reason, auditParams)
	if err != nil {
		return CertificateResponse{}, err
	}

	return toCertificateResponse(cert), nil
}

// ReplaceCertificate replaces an issued certificate with a new replacement certificate draft.
func (s *Service) ReplaceCertificate(ctx context.Context, oldCertID, orgID, actorUserID pgtype.UUID, req ReplaceCertificateRequest) (CertificateResponse, CertificateResponse, error) {
	if err := req.Validate(); err != nil {
		return CertificateResponse{}, CertificateResponse{}, err
	}

	newCertID := StringToUUID(req.ReplacementCertificateID)
	if !newCertID.Valid {
		return CertificateResponse{}, CertificateResponse{}, core.NewAppError(core.ErrCodeBadRequest, "Invalid replacement_certificate_id UUID format")
	}

	oldAuditPayload, _ := BuildSanitizedAuditPayload(oldCertID, orgID, "", "REPLACED", &req.ReasonCode, &req.ReplacementCertificateID, nil)
	oldAuditParams := db.CreateAuditLogParams{
		ActorUserID:          actorUserID,
		TargetOrganizationID: orgID,
		Action:               "CERTIFICATE_REPLACED",
		ResourceType:         "CERTIFICATE",
		Payload:              oldAuditPayload,
	}

	oldCertStr := UUIDToString(oldCertID)
	newAuditPayload, _ := BuildSanitizedAuditPayload(newCertID, orgID, "", "ISSUED", nil, nil, &oldCertStr)
	newAuditParams := db.CreateAuditLogParams{
		ActorUserID:          actorUserID,
		TargetOrganizationID: orgID,
		Action:               "CERTIFICATE_ISSUED",
		ResourceType:         "CERTIFICATE",
		Payload:              newAuditPayload,
	}

	oldCert, newCert, err := s.repo.ReplaceCertificateTx(
		ctx, oldCertID, newCertID, orgID, actorUserID,
		req.ReasonCode, req.Reason,
		oldAuditParams, newAuditParams,
	)
	if err != nil {
		return CertificateResponse{}, CertificateResponse{}, err
	}

	return toCertificateResponse(oldCert), toCertificateResponse(newCert), nil
}

// DeleteDraft soft-deletes a certificate draft and purges its attached storage file after commit.
func (s *Service) DeleteDraft(ctx context.Context, certID, orgID, actorUserID pgtype.UUID) error {
	auditPayload, _ := BuildSanitizedAuditPayload(certID, orgID, "", "DELETED", nil, nil, nil)
	auditParams := db.CreateAuditLogParams{
		ActorUserID:          actorUserID,
		TargetOrganizationID: orgID,
		Action:               "CERTIFICATE_DRAFT_DELETED",
		ResourceType:         "CERTIFICATE",
		Payload:              auditPayload,
	}

	storageKey, err := s.repo.DeleteCertificateDraftTx(ctx, certID, orgID, auditParams)
	if err != nil {
		return err
	}

	// Purge storage object synchronously post-commit with bounded retry
	if storageKey != "" {
		s.cleanupStorageObjectWithRetry(storageKey, certID, orgID)
	}

	return nil
}

// GetCertificate returns full certificate details for an organization member.
func (s *Service) GetCertificate(ctx context.Context, certID, orgID pgtype.UUID) (CertificateResponse, error) {
	cert, err := s.repo.GetCertificateByID(ctx, certID, orgID)
	if err != nil {
		return CertificateResponse{}, err
	}
	return toCertificateResponse(cert), nil
}

// ListCertificates lists certificates for an organization.
func (s *Service) ListCertificates(ctx context.Context, orgID pgtype.UUID, status, recipientEmail *string, page, limit int) ([]CertificateResponse, PaginationResponse, error) {
	page, limit = SanitizePaginationParams(page, limit)
	offset := (page - 1) * limit

	params := db.ListCertificatesByOrganizationParams{
		OrganizationID: orgID,
		Limit:          int32(limit),
		Offset:         int32(offset),
	}
	if status != nil && *status != "" {
		params.Status = pgtype.Text{String: strings.ToUpper(strings.TrimSpace(*status)), Valid: true}
	}
	if recipientEmail != nil && *recipientEmail != "" {
		params.RecipientEmail = pgtype.Text{String: strings.ToLower(strings.TrimSpace(*recipientEmail)), Valid: true}
	}

	certs, err := s.repo.ListCertificatesByOrganization(ctx, params)
	if err != nil {
		return nil, PaginationResponse{}, err
	}

	countParams := db.CountCertificatesByOrganizationParams{
		OrganizationID: orgID,
		Status:         params.Status,
		RecipientEmail: params.RecipientEmail,
	}
	total, err := s.repo.CountCertificatesByOrganization(ctx, countParams)
	if err != nil {
		return nil, PaginationResponse{}, err
	}

	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	if totalPages < 1 {
		totalPages = 1
	}

	responses := make([]CertificateResponse, 0, len(certs))
	for _, c := range certs {
		responses = append(responses, toCertificateResponse(c))
	}

	pagination := PaginationResponse{
		Page:         page,
		Limit:        limit,
		TotalRecords: total,
		TotalPages:   totalPages,
	}

	return responses, pagination, nil
}

// ListStudentCertificates lists all issued/finalized certificates for the authenticated student.
func (s *Service) ListStudentCertificates(ctx context.Context, studentUserID pgtype.UUID, status *string, page, limit int) ([]StudentCertificateResponse, PaginationResponse, error) {
	page, limit = SanitizePaginationParams(page, limit)
	offset := (page - 1) * limit

	params := db.ListCertificatesByRecipientParams{
		RecipientUserID: studentUserID,
		Limit:           int32(limit),
		Offset:          int32(offset),
	}
	if status != nil && *status != "" {
		params.Status = pgtype.Text{String: strings.ToUpper(strings.TrimSpace(*status)), Valid: true}
	}

	rows, err := s.repo.ListCertificatesByRecipient(ctx, params)
	if err != nil {
		return nil, PaginationResponse{}, err
	}

	countParams := db.CountCertificatesByRecipientParams{
		RecipientUserID: studentUserID,
		Status:          params.Status,
	}
	total, err := s.repo.CountCertificatesByRecipient(ctx, countParams)
	if err != nil {
		return nil, PaginationResponse{}, err
	}

	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	if totalPages < 1 {
		totalPages = 1
	}

	responses := make([]StudentCertificateResponse, 0, len(rows))
	for _, r := range rows {
		responses = append(responses, toStudentCertificateResponse(r))
	}

	pagination := PaginationResponse{
		Page:         page,
		Limit:        limit,
		TotalRecords: total,
		TotalPages:   totalPages,
	}

	return responses, pagination, nil
}

// GetStudentCertificate returns certificate details for the student owner.
func (s *Service) GetStudentCertificate(ctx context.Context, certID, studentUserID pgtype.UUID) (StudentCertificateResponse, error) {
	// Query recipient certificate list matching certID
	rows, err := s.repo.ListCertificatesByRecipient(ctx, db.ListCertificatesByRecipientParams{
		RecipientUserID: studentUserID,
		Limit:           100,
		Offset:          0,
	})
	if err != nil {
		return StudentCertificateResponse{}, err
	}

	for _, r := range rows {
		if UUIDEqual(r.ID, certID) {
			return toStudentCertificateResponse(r), nil
		}
	}

	return StudentCertificateResponse{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
}

// DownloadCertificate determines download eligibility and returns presigned download URL or status metadata.
func (s *Service) DownloadCertificate(ctx context.Context, certID, actorUserID pgtype.UUID, isIssuer bool, orgID *pgtype.UUID) (*DownloadResult, error) {
	var cert db.Certificate
	var err error

	if isIssuer && orgID != nil {
		cert, err = s.repo.GetCertificateByID(ctx, certID, *orgID)
	} else {
		// Student lookup: search recipient records
		rows, lookupErr := s.repo.ListCertificatesByRecipient(ctx, db.ListCertificatesByRecipientParams{
			RecipientUserID: actorUserID,
			Limit:           100,
			Offset:          0,
		})
		if lookupErr != nil {
			return nil, lookupErr
		}
		found := false
		for _, r := range rows {
			if UUIDEqual(r.ID, certID) {
				cert = db.Certificate{
					ID:                      r.ID,
					PublicID:                r.PublicID,
					OrganizationID:          r.OrganizationID,
					RecipientUserID:         r.RecipientUserID,
					Status:                  r.Status,
					FileStorageKey:          r.FileStorageKey,
					FileName:                r.FileName,
					RevocationReasonCode:    r.RevocationReasonCode,
					RevokedAt:               r.RevokedAt,
					ReplacedByCertificateID: r.ReplacedByCertificateID,
				}
				found = true
				break
			}
		}
		if !found {
			return nil, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
		}
	}

	if err != nil {
		return nil, err
	}

	if !cert.FileStorageKey.Valid || cert.FileStorageKey.String == "" {
		return nil, core.NewAppError(core.ErrCodeCertificateNotFound, "No document file attached to this certificate")
	}

	fileName := "certificate.pdf"
	if cert.FileName.Valid && cert.FileName.String != "" {
		fileName = cert.FileName.String
	}

	// Download Lifecycle Rules
	switch cert.Status {
	case "DRAFT":
		if !isIssuer {
			// Students must receive uniform 404 for draft certificates
			return nil, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
		}
		url, err := s.storage.GeneratePresignedURL(ctx, cert.FileStorageKey.String, s.presignTTL)
		if err != nil {
			return nil, core.NewAppError(core.ErrCodeInternal, "Failed to generate download URL")
		}
		return &DownloadResult{
			PresignedURL: url,
			FileName:     fileName,
			Status:       "DRAFT",
			Headers: map[string]string{
				"Cache-Control": "private, no-store",
			},
		}, nil

	case "ISSUED":
		url, err := s.storage.GeneratePresignedURL(ctx, cert.FileStorageKey.String, s.presignTTL)
		if err != nil {
			return nil, core.NewAppError(core.ErrCodeInternal, "Failed to generate download URL")
		}
		return &DownloadResult{
			PresignedURL: url,
			FileName:     fileName,
			Status:       "ISSUED",
			Headers: map[string]string{
				"Cache-Control": "private, no-store",
			},
		}, nil

	case "REVOKED":
		if !isIssuer {
			// Student receives 410 Gone with status metadata
			var reasonCode, revokedAtStr *string
			if cert.RevocationReasonCode.Valid {
				rc := cert.RevocationReasonCode.String
				reasonCode = &rc
			}
			if cert.RevokedAt.Valid {
				ra := cert.RevokedAt.Time.UTC().Format(time.RFC3339)
				revokedAtStr = &ra
			}
			return &DownloadResult{
				Status: "REVOKED",
				DeniedResponse: &CertificateStatusMetadataResponse{
					CertificateID:        UUIDToString(cert.ID),
					PublicID:             cert.PublicID,
					Status:               "REVOKED",
					RevocationReasonCode: reasonCode,
					RevokedAt:            revokedAtStr,
					Message:              "This certificate has been revoked and is no longer available for student download.",
				},
				Headers: map[string]string{
					"X-Certificate-Status": "REVOKED",
				},
			}, nil
		}

		// Issuer audit access allowed
		url, err := s.storage.GeneratePresignedURL(ctx, cert.FileStorageKey.String, s.presignTTL)
		if err != nil {
			return nil, core.NewAppError(core.ErrCodeInternal, "Failed to generate download URL")
		}
		return &DownloadResult{
			PresignedURL: url,
			FileName:     fileName,
			Status:       "REVOKED",
			Headers: map[string]string{
				"Cache-Control":        "private, no-store",
				"X-Certificate-Status": "REVOKED",
			},
		}, nil

	case "REPLACED":
		if !isIssuer {
			// Student receives 410 Gone with replacement public ID
			if !cert.ReplacedByCertificateID.Valid {
				return nil, core.NewAppError(core.ErrCodeInternal, "Certificate replacement lineage is inconsistent")
			}
			repCert, err := s.repo.GetCertificateByID(ctx, cert.ReplacedByCertificateID, cert.OrganizationID)
			if err != nil || repCert.PublicID == "" {
				return nil, core.NewAppError(core.ErrCodeInternal, "Certificate replacement lineage is inconsistent")
			}
			replacedByPublicID := &repCert.PublicID

			var reasonCode, revokedAtStr *string
			if cert.RevocationReasonCode.Valid {
				rc := cert.RevocationReasonCode.String
				reasonCode = &rc
			}
			if cert.RevokedAt.Valid {
				ra := cert.RevokedAt.Time.UTC().Format(time.RFC3339)
				revokedAtStr = &ra
			}

			return &DownloadResult{
				Status: "REPLACED",
				DeniedResponse: &CertificateStatusMetadataResponse{
					CertificateID:        UUIDToString(cert.ID),
					PublicID:             cert.PublicID,
					Status:               "REPLACED",
					RevocationReasonCode: reasonCode,
					RevokedAt:            revokedAtStr,
					ReplacedByPublicID:   replacedByPublicID,
					Message:              "This certificate has been replaced by an updated version.",
				},
				Headers: map[string]string{
					"X-Certificate-Status": "REPLACED",
				},
			}, nil
		}

		// Issuer audit access allowed
		url, err := s.storage.GeneratePresignedURL(ctx, cert.FileStorageKey.String, s.presignTTL)
		if err != nil {
			return nil, core.NewAppError(core.ErrCodeInternal, "Failed to generate download URL")
		}
		headers := map[string]string{
			"Cache-Control":        "private, no-store",
			"X-Certificate-Status": "REPLACED",
		}
		if cert.ReplacedByCertificateID.Valid {
			if repCert, err := s.repo.GetCertificateByID(ctx, cert.ReplacedByCertificateID, cert.OrganizationID); err == nil && repCert.PublicID != "" {
				headers["X-Replaced-By"] = repCert.PublicID
			}
		}
		return &DownloadResult{
			PresignedURL: url,
			FileName:     fileName,
			Status:       "REPLACED",
			Headers:      headers,
		}, nil
	}

	return nil, core.NewAppError(core.ErrCodeBadRequest, "Invalid certificate status")
}

// VerifyPublicCertificate returns the safe public projection with masked recipient name.
func (s *Service) VerifyPublicCertificate(ctx context.Context, publicID string) (PublicCertificateResponse, error) {
	publicID = strings.TrimSpace(publicID)
	if publicID == "" {
		return PublicCertificateResponse{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
	}

	row, err := s.repo.GetCertificateByPublicID(ctx, publicID)
	if err != nil {
		return PublicCertificateResponse{}, err
	}

	resp := PublicCertificateResponse{
		PublicID:                 row.PublicID,
		Status:                   row.Status,
		Title:                    row.Title,
		DegreeType:               row.DegreeType,
		GraduationDate:           FormatDateString(row.GraduationDate.Time),
		IssueDate:                FormatDateString(row.IssueDate.Time),
		DocumentHash:             row.DocumentHash.String,
		IssuerOrganizationName:   row.IssuerOrganizationName,
		IssuerOrganizationDomain: row.IssuerOrganizationDomain,
		IssuerCountryCode:        row.IssuerCountryCode,
		MaskedRecipientName:      MaskRecipientName(row.RecipientName),
	}

	if row.Major.Valid {
		m := row.Major.String
		resp.Major = &m
	}
	if row.RevocationReasonCode.Valid {
		rc := row.RevocationReasonCode.String
		resp.RevocationReasonCode = &rc
	}
	if row.RevokedAt.Valid {
		ra := row.RevokedAt.Time.UTC().Format(time.RFC3339)
		resp.RevokedAt = &ra
	}
	if row.ReplacedByPublicID.Valid {
		rb := row.ReplacedByPublicID.String
		resp.ReplacedByPublicID = &rb
	}

	if s.anchoringProvider != nil {
		if anchorData, err := s.anchoringProvider.GetCertificateAnchoring(ctx, row.PublicID); err == nil && anchorData != nil {
			resp.Anchoring = anchorData
		}
	}

	return resp, nil
}

// compensateNewUpload deletes newly uploaded storage object after a DB attach failure.
// Uses a dedicated bounded context independent of the request lifecycle.
func (s *Service) compensateNewUpload(key string, certID, orgID pgtype.UUID) {
	if strings.TrimSpace(key) == "" {
		return
	}
	compCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.storage.DeleteObject(compCtx, key); err != nil {
		s.logger.Error("storage upload compensation failed",
			slog.String("certificate_id", UUIDToString(certID)),
			slog.String("organization_id", UUIDToString(orgID)),
		)
	}
}

// cleanupStorageObjectWithRetry executes bounded post-commit object cleanup (3 attempts with exponential backoff).
// Uses a dedicated bounded context independent of request context; never rolls back committed DB operations.
func (s *Service) cleanupStorageObjectWithRetry(key string, certID, orgID pgtype.UUID) {
	if strings.TrimSpace(key) == "" {
		return
	}

	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	backoffs := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond}

	for attempt := 0; attempt < 3; attempt++ {
		if cleanupCtx.Err() != nil {
			break
		}
		err := s.storage.DeleteObject(cleanupCtx, key)
		if err == nil {
			return
		}
		if attempt < 2 {
			s.sleeper(backoffs[attempt])
		}
	}

	// Final failure logged with strictly sanitized IDs only (no full keys, hashes, URLs, credentials, or PII)
	s.logger.Error("storage cleanup failure: orphaned draft object requires operational purge",
		slog.String("certificate_id", UUIDToString(certID)),
		slog.String("organization_id", UUIDToString(orgID)),
	)
}

func generatePublicID() (string, error) {
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "TD-CERT-" + strings.ToUpper(hex.EncodeToString(bytes)), nil
}

func toCertificateResponse(c db.Certificate) CertificateResponse {
	resp := CertificateResponse{
		ID:              UUIDToString(c.ID),
		PublicID:        c.PublicID,
		OrganizationID:  UUIDToString(c.OrganizationID),
		RecipientUserID: UUIDToString(c.RecipientUserID),
		RecipientName:   c.RecipientName,
		RecipientEmail:  c.RecipientEmail,
		Title:           c.Title,
		DegreeType:      c.DegreeType,
		GraduationDate:  FormatDateString(c.GraduationDate.Time),
		IssueDate:       FormatDateString(c.IssueDate.Time),
		Status:          c.Status,
		CreatedByUserID: UUIDToString(c.CreatedByUserID),
		CreatedAt:       c.CreatedAt.Time.UTC().Format(time.RFC3339),
		UpdatedAt:       c.UpdatedAt.Time.UTC().Format(time.RFC3339),
	}

	if c.StudentIDNumber.Valid {
		sid := c.StudentIDNumber.String
		resp.StudentIDNumber = &sid
	}
	if c.Major.Valid {
		m := c.Major.String
		resp.Major = &m
	}
	if c.GradeOrHonors.Valid {
		g := c.GradeOrHonors.String
		resp.GradeOrHonors = &g
	}
	if c.FileStorageKey.Valid {
		k := c.FileStorageKey.String
		resp.FileStorageKey = &k
	}
	if c.FileName.Valid {
		fn := c.FileName.String
		resp.FileName = &fn
	}
	if c.FileSize.Valid {
		fs := c.FileSize.Int64
		resp.FileSize = &fs
	}
	if c.FileMimeType.Valid {
		fmtStr := c.FileMimeType.String
		resp.FileMimeType = &fmtStr
	}
	if c.DocumentHash.Valid {
		dh := c.DocumentHash.String
		resp.DocumentHash = &dh
	}
	if c.IssuedByUserID.Valid {
		ibu := UUIDToString(c.IssuedByUserID)
		resp.IssuedByUserID = &ibu
	}
	if c.IssuedAt.Valid {
		ia := c.IssuedAt.Time.UTC().Format(time.RFC3339)
		resp.IssuedAt = &ia
	}
	if c.RevokedByUserID.Valid {
		rbu := UUIDToString(c.RevokedByUserID)
		resp.RevokedByUserID = &rbu
	}
	if c.RevokedAt.Valid {
		ra := c.RevokedAt.Time.UTC().Format(time.RFC3339)
		resp.RevokedAt = &ra
	}
	if c.RevocationReasonCode.Valid {
		rc := c.RevocationReasonCode.String
		resp.RevocationReasonCode = &rc
	}
	if c.RevocationReason.Valid {
		rr := c.RevocationReason.String
		resp.RevocationReason = &rr
	}
	if c.ReplacedByCertificateID.Valid {
		rb := UUIDToString(c.ReplacedByCertificateID)
		resp.ReplacedByCertificateID = &rb
	}
	if c.ReplacesCertificateID.Valid {
		rp := UUIDToString(c.ReplacesCertificateID)
		resp.ReplacesCertificateID = &rp
	}

	return resp
}

func toStudentCertificateResponse(r db.ListCertificatesByRecipientRow) StudentCertificateResponse {
	resp := StudentCertificateResponse{
		ID:                    UUIDToString(r.ID),
		PublicID:              r.PublicID,
		OrganizationID:        UUIDToString(r.OrganizationID),
		OrganizationLegalName: r.OrganizationLegalName,
		OrganizationDomain:    r.OrganizationDomain,
		RecipientName:         r.RecipientName,
		Title:                 r.Title,
		DegreeType:            r.DegreeType,
		GraduationDate:        FormatDateString(r.GraduationDate.Time),
		IssueDate:             FormatDateString(r.IssueDate.Time),
		Status:                r.Status,
	}

	if r.StudentIDNumber.Valid {
		sid := r.StudentIDNumber.String
		resp.StudentIDNumber = &sid
	}
	if r.Major.Valid {
		m := r.Major.String
		resp.Major = &m
	}
	if r.GradeOrHonors.Valid {
		g := r.GradeOrHonors.String
		resp.GradeOrHonors = &g
	}
	if r.FileName.Valid {
		fn := r.FileName.String
		resp.FileName = &fn
	}
	if r.FileSize.Valid {
		fs := r.FileSize.Int64
		resp.FileSize = &fs
	}
	if r.DocumentHash.Valid {
		dh := r.DocumentHash.String
		resp.DocumentHash = &dh
	}
	if r.IssuedAt.Valid {
		ia := r.IssuedAt.Time.UTC().Format(time.RFC3339)
		resp.IssuedAt = &ia
	}
	if r.RevokedAt.Valid {
		ra := r.RevokedAt.Time.UTC().Format(time.RFC3339)
		resp.RevokedAt = &ra
	}
	if r.RevocationReasonCode.Valid {
		rc := r.RevocationReasonCode.String
		resp.RevocationReasonCode = &rc
	}
	if r.ReplacedByCertificateID.Valid {
		rb := UUIDToString(r.ReplacedByCertificateID)
		resp.ReplacedByPublicID = &rb
	}

	return resp
}
