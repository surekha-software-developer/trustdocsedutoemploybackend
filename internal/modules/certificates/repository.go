package certificates

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

// Repository defines the data access contract for the certificates module.
type Repository interface {
	CreateDraftTx(ctx context.Context, params db.CreateCertificateDraftParams, auditParams db.CreateAuditLogParams) (db.Certificate, error)
	UpdateDraftTx(ctx context.Context, params db.UpdateCertificateDraftParams, auditParams db.CreateAuditLogParams) (db.Certificate, error)
	AttachFileTx(ctx context.Context, params db.AttachCertificateFileParams, auditParams db.CreateAuditLogParams) (db.Certificate, error)
	GetCertificateByID(ctx context.Context, id, orgID pgtype.UUID) (db.Certificate, error)
	GetCertificateByIDForUpdate(ctx context.Context, id, orgID pgtype.UUID) (db.Certificate, error)
	GetCertificateByPublicID(ctx context.Context, publicID string) (db.GetCertificateByPublicIDRow, error)
	IssueCertificateTx(ctx context.Context, certID, orgID, actorUserID pgtype.UUID, auditParams db.CreateAuditLogParams) (db.Certificate, error)
	RevokeCertificateTx(ctx context.Context, certID, orgID, actorUserID pgtype.UUID, reasonCode, reason string, auditParams db.CreateAuditLogParams) (db.Certificate, error)
	ReplaceCertificateTx(ctx context.Context, oldCertID, newCertID, orgID, actorUserID pgtype.UUID, reasonCode, reason string, oldAuditParams, newAuditParams db.CreateAuditLogParams) (db.Certificate, db.Certificate, error)
	DeleteCertificateDraftTx(ctx context.Context, certID, orgID pgtype.UUID, auditParams db.CreateAuditLogParams) (string, error)
	ListCertificatesByOrganization(ctx context.Context, params db.ListCertificatesByOrganizationParams) ([]db.Certificate, error)
	CountCertificatesByOrganization(ctx context.Context, params db.CountCertificatesByOrganizationParams) (int64, error)
	ListCertificatesByRecipient(ctx context.Context, params db.ListCertificatesByRecipientParams) ([]db.ListCertificatesByRecipientRow, error)
	CountCertificatesByRecipient(ctx context.Context, params db.CountCertificatesByRecipientParams) (int64, error)
	CheckDocumentHashConflict(ctx context.Context, hash string) (bool, error)
	GetRecipientUser(ctx context.Context, userID pgtype.UUID) (db.User, error)
	GetOrganization(ctx context.Context, orgID pgtype.UUID) (db.Organization, error)
}

// PgxRepository implements Repository using a pgx connection pool and sqlc queries.
type PgxRepository struct {
	pool    *pgxpool.Pool
	queries *db.Queries
}

// NewPgxRepository constructs a new PgxRepository.
func NewPgxRepository(pool *pgxpool.Pool) *PgxRepository {
	return &PgxRepository{
		pool:    pool,
		queries: db.New(pool),
	}
}

// CreateDraftTx creates a new certificate draft and an audit record inside a single database transaction.
func (r *PgxRepository) CreateDraftTx(ctx context.Context, params db.CreateCertificateDraftParams, auditParams db.CreateAuditLogParams) (db.Certificate, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return db.Certificate{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	qtx := r.queries.WithTx(tx)

	// Validate recipient user exists
	recipient, err := qtx.GetUserByID(ctx, params.RecipientUserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Certificate{}, core.NewAppError(core.ErrCodeRecipientNotFound, "Recipient user does not exist")
		}
		return db.Certificate{}, err
	}
	if recipient.DeletedAt.Valid {
		return db.Certificate{}, core.NewAppError(core.ErrCodeRecipientNotFound, "Recipient user account is deactivated")
	}

	// Validate recipient email corresponds to recipient user
	if recipient.Email != params.RecipientEmail {
		return db.Certificate{}, core.NewAppError(core.ErrCodeRecipientMismatch, "Recipient email does not match user account email")
	}

	cert, err := qtx.CreateCertificateDraft(ctx, params)
	if err != nil {
		return db.Certificate{}, classifyDBError(err)
	}

	auditParams.TargetOrganizationID = cert.OrganizationID
	auditParams.ResourceID = cert.ID
	if _, err := qtx.CreateAuditLog(ctx, auditParams); err != nil {
		return db.Certificate{}, fmt.Errorf("failed to create audit log: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return db.Certificate{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return cert, nil
}

// UpdateDraftTx updates metadata on an unissued certificate draft.
func (r *PgxRepository) UpdateDraftTx(ctx context.Context, params db.UpdateCertificateDraftParams, auditParams db.CreateAuditLogParams) (db.Certificate, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return db.Certificate{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	qtx := r.queries.WithTx(tx)

	// Verify recipient if updating recipient fields
	if params.RecipientUserID.Valid {
		recipient, err := qtx.GetUserByID(ctx, params.RecipientUserID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return db.Certificate{}, core.NewAppError(core.ErrCodeRecipientNotFound, "Recipient user does not exist")
			}
			return db.Certificate{}, err
		}
		if recipient.DeletedAt.Valid {
			return db.Certificate{}, core.NewAppError(core.ErrCodeRecipientNotFound, "Recipient user account is deactivated")
		}
		if params.RecipientEmail.Valid && recipient.Email != params.RecipientEmail.String {
			return db.Certificate{}, core.NewAppError(core.ErrCodeRecipientMismatch, "Recipient email does not match user account email")
		}
	}

	cert, err := qtx.UpdateCertificateDraft(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate draft not found or cannot be modified")
		}
		return db.Certificate{}, classifyDBError(err)
	}

	auditParams.TargetOrganizationID = cert.OrganizationID
	auditParams.ResourceID = cert.ID
	if _, err := qtx.CreateAuditLog(ctx, auditParams); err != nil {
		return db.Certificate{}, fmt.Errorf("failed to create audit log: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return db.Certificate{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return cert, nil
}

// AttachFileTx attaches file metadata to a draft certificate.
func (r *PgxRepository) AttachFileTx(ctx context.Context, params db.AttachCertificateFileParams, auditParams db.CreateAuditLogParams) (db.Certificate, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return db.Certificate{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	qtx := r.queries.WithTx(tx)

	cert, err := qtx.AttachCertificateFile(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate draft not found or already finalized")
		}
		return db.Certificate{}, classifyDBError(err)
	}

	auditParams.TargetOrganizationID = cert.OrganizationID
	auditParams.ResourceID = cert.ID
	if _, err := qtx.CreateAuditLog(ctx, auditParams); err != nil {
		return db.Certificate{}, fmt.Errorf("failed to create audit log: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return db.Certificate{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return cert, nil
}

// GetCertificateByID returns a non-deleted certificate by its primary key and organization ID.
func (r *PgxRepository) GetCertificateByID(ctx context.Context, id, orgID pgtype.UUID) (db.Certificate, error) {
	cert, err := r.queries.GetCertificateByID(ctx, db.GetCertificateByIDParams{
		ID:             id,
		OrganizationID: orgID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
		}
		return db.Certificate{}, err
	}
	return cert, nil
}

// GetCertificateByIDForUpdate locks the certificate row within the current transaction.
func (r *PgxRepository) GetCertificateByIDForUpdate(ctx context.Context, id, orgID pgtype.UUID) (db.Certificate, error) {
	cert, err := r.queries.GetCertificateByIDForUpdate(ctx, db.GetCertificateByIDForUpdateParams{
		ID:             id,
		OrganizationID: orgID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
		}
		return db.Certificate{}, err
	}
	return cert, nil
}

// GetCertificateByPublicID returns safe public verification details.
func (r *PgxRepository) GetCertificateByPublicID(ctx context.Context, publicID string) (db.GetCertificateByPublicIDRow, error) {
	row, err := r.queries.GetCertificateByPublicID(ctx, publicID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.GetCertificateByPublicIDRow{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
		}
		return db.GetCertificateByPublicIDRow{}, err
	}
	return row, nil
}

// IssueCertificateTx finalizes and issues a draft certificate transactionally.
func (r *PgxRepository) IssueCertificateTx(ctx context.Context, certID, orgID, actorUserID pgtype.UUID, auditParams db.CreateAuditLogParams) (db.Certificate, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return db.Certificate{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	qtx := r.queries.WithTx(tx)

	// 1. Lock certificate row
	cert, err := qtx.GetCertificateByIDForUpdate(ctx, db.GetCertificateByIDForUpdateParams{
		ID:             certID,
		OrganizationID: orgID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
		}
		return db.Certificate{}, err
	}

	// 2. Validate prerequisites
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
		return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateFileRequired, "Certificate must have a PDF document attached before issuance")
	}

	// 3. Lock and verify university organization
	org, err := qtx.GetOrganizationByID(ctx, orgID)
	if err != nil || org.DeletedAt.Valid {
		return db.Certificate{}, core.NewAppError(core.ErrCodeForbidden, "Organization not found or inactive")
	}
	if org.VerificationStatus != "VERIFIED" || org.OrgType != "UNIVERSITY" {
		return db.Certificate{}, core.NewAppError(core.ErrCodeForbidden, "Only verified universities may issue certificates")
	}

	// 4. Validate issue date is not in the future relative to current time
	if cert.IssueDate.Valid {
		today := time.Now().UTC().Truncate(24 * time.Hour)
		certDate := cert.IssueDate.Time.UTC().Truncate(24 * time.Hour)
		if certDate.After(today) {
			return db.Certificate{}, core.NewAppError(core.ErrCodeFutureIssueDate, "Certificate issue_date cannot be in the future")
		}
	}

	// 5. Check finalized document hash conflict
	conflict, err := qtx.CheckDocumentHashConflict(ctx, cert.DocumentHash)
	if err != nil {
		return db.Certificate{}, err
	}
	if conflict {
		return db.Certificate{}, core.NewAppError(core.ErrCodeDuplicateDocumentHash, "A certificate with identical cryptographic document bytes has already been issued")
	}

	// 6. Execute issuance
	issuedCert, err := qtx.IssueCertificate(ctx, db.IssueCertificateParams{
		ID:             certID,
		OrganizationID: orgID,
		IssuedByUserID: actorUserID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateStateConflict, "Certificate does not meet issuance preconditions or was concurrently modified")
		}
		return db.Certificate{}, classifyDBError(err)
	}

	// 7. Write audit log
	auditParams.TargetOrganizationID = orgID
	auditParams.ResourceID = certID
	if _, err := qtx.CreateAuditLog(ctx, auditParams); err != nil {
		return db.Certificate{}, fmt.Errorf("failed to create audit log: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return db.Certificate{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return issuedCert, nil
}

// RevokeCertificateTx revokes an issued certificate transactionally.
func (r *PgxRepository) RevokeCertificateTx(ctx context.Context, certID, orgID, actorUserID pgtype.UUID, reasonCode, reason string, auditParams db.CreateAuditLogParams) (db.Certificate, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return db.Certificate{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	qtx := r.queries.WithTx(tx)

	// Lock certificate row
	cert, err := qtx.GetCertificateByIDForUpdate(ctx, db.GetCertificateByIDForUpdateParams{
		ID:             certID,
		OrganizationID: orgID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
		}
		return db.Certificate{}, err
	}

	if cert.Status != "ISSUED" {
		if cert.Status == "REVOKED" {
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateRevoked, "Certificate is already revoked")
		}
		if cert.Status == "REPLACED" {
			return db.Certificate{}, core.NewAppError(core.ErrCodeCertificateReplaced, "Certificate has already been replaced")
		}
		return db.Certificate{}, core.NewAppError(core.ErrCodeBadRequest, fmt.Sprintf("Only ISSUED certificates can be revoked; current status is '%s'", cert.Status))
	}

	revokedCert, err := qtx.RevokeCertificate(ctx, db.RevokeCertificateParams{
		ID:                   certID,
		OrganizationID:       orgID,
		RevokedByUserID:      actorUserID,
		RevocationReasonCode: pgtype.Text{String: reasonCode, Valid: true},
		RevocationReason:     pgtype.Text{String: reason, Valid: true},
	})
	if err != nil {
		return db.Certificate{}, classifyDBError(err)
	}

	auditParams.TargetOrganizationID = orgID
	auditParams.ResourceID = certID
	if _, err := qtx.CreateAuditLog(ctx, auditParams); err != nil {
		return db.Certificate{}, fmt.Errorf("failed to create audit log: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return db.Certificate{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return revokedCert, nil
}

// ReplaceCertificateTx atomically marks an old certificate as REPLACED and issues a new replacement certificate.
// Rows are locked in deterministic UUID order to eliminate potential deadlocks.
func (r *PgxRepository) ReplaceCertificateTx(
	ctx context.Context,
	oldCertID, newCertID, orgID, actorUserID pgtype.UUID,
	reasonCode, reason string,
	oldAuditParams, newAuditParams db.CreateAuditLogParams,
) (db.Certificate, db.Certificate, error) {
	if bytes.Equal(oldCertID.Bytes[:], newCertID.Bytes[:]) {
		return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeSelfReplacementProhibited, "A certificate cannot replace itself")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return db.Certificate{}, db.Certificate{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	qtx := r.queries.WithTx(tx)

	// Deterministic UUID locking order
	var firstID, secondID pgtype.UUID
	if bytes.Compare(oldCertID.Bytes[:], newCertID.Bytes[:]) < 0 {
		firstID = oldCertID
		secondID = newCertID
	} else {
		firstID = newCertID
		secondID = oldCertID
	}

	certFirst, err := qtx.GetCertificateByIDForUpdate(ctx, db.GetCertificateByIDForUpdateParams{ID: firstID, OrganizationID: orgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
		}
		return db.Certificate{}, db.Certificate{}, err
	}

	certSecond, err := qtx.GetCertificateByIDForUpdate(ctx, db.GetCertificateByIDForUpdateParams{ID: secondID, OrganizationID: orgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate not found")
		}
		return db.Certificate{}, db.Certificate{}, err
	}

	var oldCert, newCert db.Certificate
	if bytes.Equal(firstID.Bytes[:], oldCertID.Bytes[:]) {
		oldCert = certFirst
		newCert = certSecond
	} else {
		oldCert = certSecond
		newCert = certFirst
	}

	// Validate original certificate status
	if oldCert.Status != "ISSUED" {
		if oldCert.Status == "REPLACED" {
			return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeCertificateReplaced, "Original certificate is already marked as replaced")
		}
		if oldCert.Status == "REVOKED" {
			return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeCertificateRevoked, "Original certificate is revoked and cannot be replaced")
		}
		return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeBadRequest, fmt.Sprintf("Original certificate must be in 'ISSUED' status; current is '%s'", oldCert.Status))
	}

	// Validate replacement draft status
	if newCert.Status != "DRAFT" {
		return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeCertificateNotDraft, fmt.Sprintf("Replacement certificate must be in 'DRAFT' status; current is '%s'", newCert.Status))
	}

	// Validate recipient match
	if !bytes.Equal(oldCert.RecipientUserID.Bytes[:], newCert.RecipientUserID.Bytes[:]) {
		return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeRecipientMismatch, "Replacement certificate recipient must match original certificate recipient")
	}

	// Validate file attached to replacement draft
	if !newCert.FileStorageKey.Valid || !newCert.DocumentHash.Valid {
		return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeCertificateFileRequired, "Replacement draft must have an attached PDF file before issuance")
	}

	// Validate document hash differs
	if oldCert.DocumentHash.Valid && oldCert.DocumentHash.String == newCert.DocumentHash.String {
		return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeDuplicateDocumentHash, "Replacement certificate cannot have the exact same document hash as the original")
	}

	// Check if replacement hash is already claimed by another finalized certificate
	conflict, err := qtx.CheckDocumentHashConflict(ctx, newCert.DocumentHash)
	if err != nil {
		return db.Certificate{}, db.Certificate{}, err
	}
	if conflict {
		return db.Certificate{}, db.Certificate{}, core.NewAppError(core.ErrCodeDuplicateDocumentHash, "Replacement document hash conflicts with an existing finalized certificate")
	}

	// Issue replacement certificate
	issuedReplacement, err := qtx.IssueReplacementCertificate(ctx, db.IssueReplacementCertificateParams{
		ID:                    newCertID,
		OrganizationID:        orgID,
		IssuedByUserID:        actorUserID,
		ReplacesCertificateID: oldCertID,
	})
	if err != nil {
		return db.Certificate{}, db.Certificate{}, classifyDBError(err)
	}

	// Mark original as replaced
	markedReplaced, err := qtx.MarkCertificateReplaced(ctx, db.MarkCertificateReplacedParams{
		ID:                      oldCertID,
		OrganizationID:          orgID,
		RevokedByUserID:         actorUserID,
		RevocationReasonCode:    pgtype.Text{String: reasonCode, Valid: true},
		RevocationReason:        pgtype.Text{String: reason, Valid: true},
		ReplacedByCertificateID: newCertID,
	})
	if err != nil {
		return db.Certificate{}, db.Certificate{}, classifyDBError(err)
	}

	// Audit logs for both records
	oldAuditParams.TargetOrganizationID = orgID
	oldAuditParams.ResourceID = oldCertID
	if _, err := qtx.CreateAuditLog(ctx, oldAuditParams); err != nil {
		return db.Certificate{}, db.Certificate{}, fmt.Errorf("failed to log audit for original certificate: %w", err)
	}

	newAuditParams.TargetOrganizationID = orgID
	newAuditParams.ResourceID = newCertID
	if _, err := qtx.CreateAuditLog(ctx, newAuditParams); err != nil {
		return db.Certificate{}, db.Certificate{}, fmt.Errorf("failed to log audit for replacement certificate: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return db.Certificate{}, db.Certificate{}, fmt.Errorf("failed to commit replacement transaction: %w", err)
	}

	return markedReplaced, issuedReplacement, nil
}

// DeleteCertificateDraftTx soft-deletes an unissued draft and returns its storage key for post-commit purge.
func (r *PgxRepository) DeleteCertificateDraftTx(ctx context.Context, certID, orgID pgtype.UUID, auditParams db.CreateAuditLogParams) (string, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	qtx := r.queries.WithTx(tx)

	row, err := qtx.DeleteCertificateDraft(ctx, db.DeleteCertificateDraftParams{
		ID:             certID,
		OrganizationID: orgID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", core.NewAppError(core.ErrCodeCertificateNotFound, "Certificate draft not found or cannot be deleted")
		}
		return "", classifyDBError(err)
	}

	auditParams.TargetOrganizationID = orgID
	auditParams.ResourceID = certID
	if _, err := qtx.CreateAuditLog(ctx, auditParams); err != nil {
		return "", fmt.Errorf("failed to create audit log: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("failed to commit transaction: %w", err)
	}

	var storageKey string
	if row.FileStorageKey.Valid {
		storageKey = row.FileStorageKey.String
	}
	return storageKey, nil
}

// ListCertificatesByOrganization queries certificates for a university tenant.
func (r *PgxRepository) ListCertificatesByOrganization(ctx context.Context, params db.ListCertificatesByOrganizationParams) ([]db.Certificate, error) {
	return r.queries.ListCertificatesByOrganization(ctx, params)
}

// CountCertificatesByOrganization counts certificates matching filter parameters.
func (r *PgxRepository) CountCertificatesByOrganization(ctx context.Context, params db.CountCertificatesByOrganizationParams) (int64, error) {
	return r.queries.CountCertificatesByOrganization(ctx, params)
}

// ListCertificatesByRecipient queries issued/finalized certificates belonging to a student.
func (r *PgxRepository) ListCertificatesByRecipient(ctx context.Context, params db.ListCertificatesByRecipientParams) ([]db.ListCertificatesByRecipientRow, error) {
	return r.queries.ListCertificatesByRecipient(ctx, params)
}

// CountCertificatesByRecipient counts certificates belonging to a student.
func (r *PgxRepository) CountCertificatesByRecipient(ctx context.Context, params db.CountCertificatesByRecipientParams) (int64, error) {
	return r.queries.CountCertificatesByRecipient(ctx, params)
}

// CheckDocumentHashConflict checks if a SHA-256 document hash is already finalized.
func (r *PgxRepository) CheckDocumentHashConflict(ctx context.Context, hash string) (bool, error) {
	return r.queries.CheckDocumentHashConflict(ctx, pgtype.Text{String: hash, Valid: true})
}

// GetRecipientUser retrieves a user by ID.
func (r *PgxRepository) GetRecipientUser(ctx context.Context, userID pgtype.UUID) (db.User, error) {
	return r.queries.GetUserByID(ctx, userID)
}

// GetOrganization retrieves an organization by ID.
func (r *PgxRepository) GetOrganization(ctx context.Context, orgID pgtype.UUID) (db.Organization, error) {
	return r.queries.GetOrganizationByID(ctx, orgID)
}

// classifyDBError translates PostgreSQL integrity violations into sanitized core errors.
func classifyDBError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.ConstraintName {
		case "idx_certificates_document_hash_finalized":
			return core.NewAppError(core.ErrCodeDuplicateDocumentHash, "A certificate with this exact document hash already exists in finalized state")
		case "chk_certificates_academic_dates":
			return core.NewAppError(core.ErrCodeInvalidAcademicDates, "Issue date cannot precede graduation date")
		case "chk_certificates_degree_type_enum":
			return core.NewAppError(core.ErrCodeInvalidDegreeType, "Invalid degree type provided")
		case "chk_certificates_status_consistency":
			return core.NewAppError(core.ErrCodeConflict, "Operation violates certificate lifecycle state invariants")
		case "chk_certificates_no_self_replacement":
			return core.NewAppError(core.ErrCodeSelfReplacementProhibited, "Certificate cannot replace itself")
		case "chk_certificates_no_direct_cycle":
			return core.NewAppError(core.ErrCodeConflict, "Direct replacement cycle detected")
		case "chk_certificates_file_consistency":
			return core.NewAppError(core.ErrCodeBadRequest, "Invalid certificate file metadata configuration")
		}
	}
	return err
}

// BuildSanitizedAuditPayload creates a sanitized JSON payload for audit logging.
// Strictly omits PII (names, emails, student IDs), document hashes, filenames, storage keys, and presigned URLs.
func BuildSanitizedAuditPayload(certID, orgID pgtype.UUID, publicID, status string, reasonCode, replacedByID, replacesID *string) ([]byte, error) {
	payload := map[string]interface{}{
		"certificate_id":  UUIDToString(certID),
		"organization_id": UUIDToString(orgID),
		"status":          status,
	}
	if publicID != "" {
		payload["public_id"] = publicID
	}
	if reasonCode != nil && *reasonCode != "" {
		payload["reason_code"] = *reasonCode
	}
	if replacedByID != nil && *replacedByID != "" {
		payload["replaced_by_certificate_id"] = *replacedByID
	}
	if replacesID != nil && *replacesID != "" {
		payload["replaces_certificate_id"] = *replacesID
	}
	return json.Marshal(payload)
}
