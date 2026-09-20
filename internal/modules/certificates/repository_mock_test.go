package certificates

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

// MockRepository provides a concurrency-safe in-memory implementation of Repository for unit tests.
type MockRepository struct {
	mu            sync.RWMutex
	certificates  map[string]db.Certificate
	users         map[string]db.User
	organizations map[string]db.Organization

	// Error hooks for simulating database failures
	FailCreateTx  error
	FailUpdateTx  error
	FailAttachTx  error
	FailIssueTx   error
	FailRevokeTx  error
	FailReplaceTx error
	FailDeleteTx  error
}

// NewMockRepository constructs an empty MockRepository.
func NewMockRepository() *MockRepository {
	return &MockRepository{
		certificates:  make(map[string]db.Certificate),
		users:         make(map[string]db.User),
		organizations: make(map[string]db.Organization),
	}
}

func (m *MockRepository) CreateDraftTx(ctx context.Context, params db.CreateCertificateDraftParams, auditParams db.CreateAuditLogParams) (db.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.FailCreateTx != nil {
		return db.Certificate{}, m.FailCreateTx
	}

	recipient, ok := m.users[UUIDToString(params.RecipientUserID)]
	if !ok || recipient.DeletedAt.Valid {
		return db.Certificate{}, core.NewAppError(core.ErrCodeRecipientNotFound, "Recipient user does not exist")
	}
	if recipient.Email != params.RecipientEmail {
		return db.Certificate{}, core.NewAppError(core.ErrCodeRecipientMismatch, "Recipient email mismatch")
	}

	certID := StringToUUID("20000000-0000-0000-0000-" + fmt.Sprintf("%012d", len(m.certificates)+1))
	cert := db.Certificate{
		ID:              certID,
		PublicID:        params.PublicID,
		OrganizationID:  params.OrganizationID,
		RecipientUserID: params.RecipientUserID,
		RecipientName:   params.RecipientName,
		RecipientEmail:  params.RecipientEmail,
		StudentIDNumber: params.StudentIDNumber,
		Title:           params.Title,
		DegreeType:      params.DegreeType,
		Major:           params.Major,
		GradeOrHonors:   params.GradeOrHonors,
		GraduationDate:  params.GraduationDate,
		IssueDate:       params.IssueDate,
		Status:          "DRAFT",
		CreatedByUserID: params.CreatedByUserID,
		CreatedAt:       pgtype.Timestamptz{Time: time.Now(), Valid: true},
		UpdatedAt:       pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}

	m.certificates[UUIDToString(certID)] = cert
	return cert, nil
}

func (m *MockRepository) UpdateDraftTx(ctx context.Context, params db.UpdateCertificateDraftParams, auditParams db.CreateAuditLogParams) (db.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.FailUpdateTx != nil {
		return db.Certificate{}, m.FailUpdateTx
	}

	cert, ok := m.certificates[UUIDToString(params.ID)]
	if !ok || cert.Status != "DRAFT" || cert.DeletedAt.Valid || !UUIDEqual(cert.OrganizationID, params.OrganizationID) {
		return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Draft not found or not in draft status")
	}

	if params.RecipientUserID.Valid {
		cert.RecipientUserID = params.RecipientUserID
	}
	if params.RecipientName.Valid {
		cert.RecipientName = params.RecipientName.String
	}
	if params.RecipientEmail.Valid {
		cert.RecipientEmail = params.RecipientEmail.String
	}
	if params.StudentIDNumber.Valid {
		cert.StudentIDNumber = params.StudentIDNumber
	}
	if params.Title.Valid {
		cert.Title = params.Title.String
	}
	if params.DegreeType.Valid {
		cert.DegreeType = params.DegreeType.String
	}
	if params.Major.Valid {
		cert.Major = params.Major
	}
	if params.GradeOrHonors.Valid {
		cert.GradeOrHonors = params.GradeOrHonors
	}
	if params.GraduationDate.Valid {
		cert.GraduationDate = params.GraduationDate
	}
	if params.IssueDate.Valid {
		cert.IssueDate = params.IssueDate
	}
	if cert.GraduationDate.Valid && cert.IssueDate.Valid && cert.IssueDate.Time.Before(cert.GraduationDate.Time) {
		return db.Certificate{}, core.NewAppError(core.ErrCodeInvalidAcademicDates, "issue_date must be on or after graduation_date")
	}
	cert.UpdatedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}

	m.certificates[UUIDToString(params.ID)] = cert
	return cert, nil
}

func (m *MockRepository) AttachFileTx(ctx context.Context, params db.AttachCertificateFileParams, auditParams db.CreateAuditLogParams) (db.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.FailAttachTx != nil {
		return db.Certificate{}, m.FailAttachTx
	}

	cert, ok := m.certificates[UUIDToString(params.ID)]
	if !ok || cert.Status != "DRAFT" || cert.DeletedAt.Valid {
		return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Draft not found or already finalized")
	}

	cert.FileStorageKey = params.FileStorageKey
	cert.FileName = params.FileName
	cert.FileSize = params.FileSize
	cert.FileMimeType = params.FileMimeType
	cert.DocumentHash = params.DocumentHash
	cert.UpdatedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}

	m.certificates[UUIDToString(params.ID)] = cert
	return cert, nil
}

func (m *MockRepository) GetCertificateByID(ctx context.Context, id, orgID pgtype.UUID) (db.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cert, ok := m.certificates[UUIDToString(id)]
	if !ok || cert.DeletedAt.Valid || !UUIDEqual(cert.OrganizationID, orgID) {
		return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
	}
	return cert, nil
}

func (m *MockRepository) GetCertificateByIDForUpdate(ctx context.Context, id, orgID pgtype.UUID) (db.Certificate, error) {
	return m.GetCertificateByID(ctx, id, orgID)
}

func (m *MockRepository) GetCertificateByPublicID(ctx context.Context, publicID string) (db.GetCertificateByPublicIDRow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, cert := range m.certificates {
		if cert.PublicID == publicID && !cert.DeletedAt.Valid && cert.Status != "DRAFT" {
			org := m.organizations[UUIDToString(cert.OrganizationID)]
			return db.GetCertificateByPublicIDRow{
				ID:                       cert.ID,
				PublicID:                 cert.PublicID,
				Status:                   cert.Status,
				Title:                    cert.Title,
				DegreeType:               cert.DegreeType,
				Major:                    cert.Major,
				GraduationDate:           cert.GraduationDate,
				IssueDate:                cert.IssueDate,
				DocumentHash:             cert.DocumentHash,
				RevocationReasonCode:     cert.RevocationReasonCode,
				RevokedAt:                cert.RevokedAt,
				RecipientName:            cert.RecipientName,
				IssuerOrganizationName:   org.LegalName,
				IssuerOrganizationDomain: org.OfficialDomain,
				IssuerCountryCode:        org.CountryCode,
			}, nil
		}
	}
	return db.GetCertificateByPublicIDRow{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
}

func (m *MockRepository) IssueCertificateTx(ctx context.Context, certID, orgID, actorUserID pgtype.UUID, auditParams db.CreateAuditLogParams) (db.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.FailIssueTx != nil {
		return db.Certificate{}, m.FailIssueTx
	}

	cert, ok := m.certificates[UUIDToString(certID)]
	if !ok || cert.DeletedAt.Valid || !UUIDEqual(cert.OrganizationID, orgID) {
		return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
	}
	if cert.Status != "DRAFT" {
		switch cert.Status {
		case "ISSUED":
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateAlreadyIssued, "Certificate has already been issued")
		case "REVOKED":
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateStateConflict, "Certificate has been revoked and cannot be issued")
		case "REPLACED":
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateStateConflict, "Certificate has been replaced and cannot be issued")
		default:
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateStateConflict, fmt.Sprintf("Certificate is in '%s' status and cannot be issued", cert.Status))
		}
	}
	if !cert.FileStorageKey.Valid || !cert.DocumentHash.Valid {
		return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateFileRequired, "Certificate must have an attached PDF")
	}

	// Check hash conflict against finalized certificates
	for _, other := range m.certificates {
		if !UUIDEqual(other.ID, cert.ID) && other.Status != "DRAFT" && !other.DeletedAt.Valid && other.DocumentHash.Valid && other.DocumentHash.String == cert.DocumentHash.String {
			return db.Certificate{}, core.NewAppError(core.ErrCodeDuplicateDocumentHash, "Duplicate document hash")
		}
	}

	cert.Status = "ISSUED"
	cert.IssuedByUserID = actorUserID
	cert.IssuedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	cert.UpdatedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}

	m.certificates[UUIDToString(certID)] = cert
	return cert, nil
}

func (m *MockRepository) RevokeCertificateTx(ctx context.Context, certID, orgID, actorUserID pgtype.UUID, reasonCode, reason string, auditParams db.CreateAuditLogParams) (db.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.FailRevokeTx != nil {
		return db.Certificate{}, m.FailRevokeTx
	}

	cert, ok := m.certificates[UUIDToString(certID)]
	if !ok || cert.DeletedAt.Valid || !UUIDEqual(cert.OrganizationID, orgID) {
		return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
	}
	if cert.Status != "ISSUED" {
		if cert.Status == "REVOKED" {
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateRevoked, "Certificate already revoked")
		}
		if cert.Status == "REPLACED" {
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateReplaced, "Certificate already replaced")
		}
		return db.Certificate{}, core.NewAppError(core.ErrCodeBadRequest, "Only ISSUED certificates may be revoked")
	}

	cert.Status = "REVOKED"
	cert.RevokedByUserID = actorUserID
	cert.RevokedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	cert.RevocationReasonCode = pgtype.Text{String: reasonCode, Valid: true}
	cert.RevocationReason = pgtype.Text{String: reason, Valid: true}
	cert.UpdatedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}

	m.certificates[UUIDToString(certID)] = cert
	return cert, nil
}

func (m *MockRepository) ReplaceCertificateTx(
	ctx context.Context,
	oldCertID, newCertID, orgID, actorUserID pgtype.UUID,
	reasonCode, reason string,
	oldAuditParams, newAuditParams db.CreateAuditLogParams,
) (db.Certificate, db.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.FailReplaceTx != nil {
		return db.Certificate{}, db.Certificate{}, m.FailReplaceTx
	}

	if UUIDEqual(oldCertID, newCertID) {
		return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeSelfReplacementProhibited, "Cannot replace self")
	}

	oldCert, okOld := m.certificates[UUIDToString(oldCertID)]
	newCert, okNew := m.certificates[UUIDToString(newCertID)]
	if !okOld || !okNew || oldCert.DeletedAt.Valid || newCert.DeletedAt.Valid {
		return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
	}

	if oldCert.Status != "ISSUED" {
		return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeBadRequest, "Original must be ISSUED")
	}
	if newCert.Status != "DRAFT" {
		return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotDraft, "Replacement must be DRAFT")
	}
	if !UUIDEqual(oldCert.RecipientUserID, newCert.RecipientUserID) {
		return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeRecipientMismatch, "Recipient mismatch")
	}
	if oldCert.DocumentHash.Valid && oldCert.DocumentHash.String == newCert.DocumentHash.String {
		return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeDuplicateDocumentHash, "Hashes cannot match")
	}

	now := time.Now()
	oldCert.Status = "REPLACED"
	oldCert.ReplacedByCertificateID = newCertID
	oldCert.RevokedByUserID = actorUserID
	oldCert.RevokedAt = pgtype.Timestamptz{Time: now, Valid: true}
	oldCert.RevocationReasonCode = pgtype.Text{String: reasonCode, Valid: true}
	oldCert.RevocationReason = pgtype.Text{String: reason, Valid: true}
	oldCert.UpdatedAt = pgtype.Timestamptz{Time: now, Valid: true}

	newCert.Status = "ISSUED"
	newCert.ReplacesCertificateID = oldCertID
	newCert.IssuedByUserID = actorUserID
	newCert.IssuedAt = pgtype.Timestamptz{Time: now, Valid: true}
	newCert.UpdatedAt = pgtype.Timestamptz{Time: now, Valid: true}

	m.certificates[UUIDToString(oldCertID)] = oldCert
	m.certificates[UUIDToString(newCertID)] = newCert

	return oldCert, newCert, nil
}

func (m *MockRepository) DeleteCertificateDraftTx(ctx context.Context, certID, orgID pgtype.UUID, auditParams db.CreateAuditLogParams) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.FailDeleteTx != nil {
		return "", m.FailDeleteTx
	}

	cert, ok := m.certificates[UUIDToString(certID)]
	if !ok || cert.DeletedAt.Valid || !UUIDEqual(cert.OrganizationID, orgID) || cert.Status != "DRAFT" {
		return "", core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate draft not found")
	}

	cert.DeletedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	m.certificates[UUIDToString(certID)] = cert

	var storageKey string
	if cert.FileStorageKey.Valid {
		storageKey = cert.FileStorageKey.String
	}
	return storageKey, nil
}

func (m *MockRepository) ListCertificatesByOrganization(ctx context.Context, params db.ListCertificatesByOrganizationParams) ([]db.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []db.Certificate
	for _, c := range m.certificates {
		if UUIDEqual(c.OrganizationID, params.OrganizationID) && !c.DeletedAt.Valid {
			if params.Status.Valid && c.Status != params.Status.String {
				continue
			}
			if params.RecipientEmail.Valid && c.RecipientEmail != params.RecipientEmail.String {
				continue
			}
			result = append(result, c)
		}
	}
	return result, nil
}

func (m *MockRepository) CountCertificatesByOrganization(ctx context.Context, params db.CountCertificatesByOrganizationParams) (int64, error) {
	list, _ := m.ListCertificatesByOrganization(ctx, db.ListCertificatesByOrganizationParams{
		OrganizationID: params.OrganizationID,
		Status:         params.Status,
		RecipientEmail: params.RecipientEmail,
	})
	return int64(len(list)), nil
}

func (m *MockRepository) ListCertificatesByRecipient(ctx context.Context, params db.ListCertificatesByRecipientParams) ([]db.ListCertificatesByRecipientRow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []db.ListCertificatesByRecipientRow
	for _, c := range m.certificates {
		if UUIDEqual(c.RecipientUserID, params.RecipientUserID) && !c.DeletedAt.Valid && c.Status != "DRAFT" {
			if params.Status.Valid && c.Status != params.Status.String {
				continue
			}
			org := m.organizations[UUIDToString(c.OrganizationID)]
			result = append(result, db.ListCertificatesByRecipientRow{
				ID:                      c.ID,
				PublicID:                c.PublicID,
				OrganizationID:          c.OrganizationID,
				RecipientUserID:         c.RecipientUserID,
				RecipientName:           c.RecipientName,
				RecipientEmail:          c.RecipientEmail,
				StudentIDNumber:         c.StudentIDNumber,
				Title:                   c.Title,
				DegreeType:              c.DegreeType,
				Major:                   c.Major,
				GradeOrHonors:           c.GradeOrHonors,
				GraduationDate:          c.GraduationDate,
				IssueDate:               c.IssueDate,
				Status:                  c.Status,
				FileName:                c.FileName,
				FileSize:                c.FileSize,
				FileStorageKey:          c.FileStorageKey,
				FileMimeType:            c.FileMimeType,
				DocumentHash:            c.DocumentHash,
				CreatedByUserID:         c.CreatedByUserID,
				CreatedAt:               c.CreatedAt,
				UpdatedAt:               c.UpdatedAt,
				IssuedByUserID:          c.IssuedByUserID,
				IssuedAt:                c.IssuedAt,
				RevokedByUserID:         c.RevokedByUserID,
				RevokedAt:               c.RevokedAt,
				RevocationReasonCode:    c.RevocationReasonCode,
				RevocationReason:        c.RevocationReason,
				ReplacedByCertificateID: c.ReplacedByCertificateID,
				ReplacesCertificateID:   c.ReplacesCertificateID,
				OrganizationLegalName:   org.LegalName,
				OrganizationDomain:      org.OfficialDomain,
			})
		}
	}
	return result, nil
}

func (m *MockRepository) CountCertificatesByRecipient(ctx context.Context, params db.CountCertificatesByRecipientParams) (int64, error) {
	list, _ := m.ListCertificatesByRecipient(ctx, db.ListCertificatesByRecipientParams{
		RecipientUserID: params.RecipientUserID,
		Status:          params.Status,
	})
	return int64(len(list)), nil
}

func (m *MockRepository) CheckDocumentHashConflict(ctx context.Context, hash string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, c := range m.certificates {
		if !c.DeletedAt.Valid && c.Status != "DRAFT" && c.DocumentHash.Valid && c.DocumentHash.String == hash {
			return true, nil
		}
	}
	return false, nil
}

func (m *MockRepository) GetRecipientUser(ctx context.Context, userID pgtype.UUID) (db.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, ok := m.users[UUIDToString(userID)]
	if !ok {
		return db.User{}, core.NewAppError(core.ErrCodeRecipientNotFound, "User not found")
	}
	return user, nil
}

func (m *MockRepository) GetOrganization(ctx context.Context, orgID pgtype.UUID) (db.Organization, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	org, ok := m.organizations[UUIDToString(orgID)]
	if !ok {
		return db.Organization{}, core.NewAppError(core.ErrCodeNotFound, "Organization not found")
	}
	return org, nil
}

// AddUser helper for test setup.
func (m *MockRepository) AddUser(user db.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[UUIDToString(user.ID)] = user
}

// AddOrganization helper for test setup.
func (m *MockRepository) AddOrganization(org db.Organization) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.organizations[UUIDToString(org.ID)] = org
}

// AddCertificate helper for test setup.
func (m *MockRepository) AddCertificate(cert db.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certificates[UUIDToString(cert.ID)] = cert
}
