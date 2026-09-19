package organizations

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

// Repository defines data access contract for organizations module.
type Repository interface {
	ApplyOrganizationTx(
		ctx context.Context,
		orgParams db.CreateOrganizationParams,
		applicantUserID pgtype.UUID,
		applicantRole string,
		auditParams db.CreateAuditLogParams,
	) (db.Organization, db.OrganizationMembership, error)

	GetOrganizationByID(ctx context.Context, id pgtype.UUID) (db.Organization, error)
	ListOrganizationsByUserID(ctx context.Context, userID pgtype.UUID) ([]db.ListOrganizationsByUserIDRow, error)
	ListOrganizationsFiltered(ctx context.Context, params db.ListOrganizationsFilteredParams) ([]db.Organization, error)
	CountOrganizationsFiltered(ctx context.Context, params db.CountOrganizationsFilteredParams) (int64, error)
	GetOrganizationApplicationForAdmin(ctx context.Context, orgID pgtype.UUID) (db.Organization, []db.ListMembershipsByOrgIDWithUserRow, error)

	ApproveOrganizationTx(
		ctx context.Context,
		orgID pgtype.UUID,
		reviewerUserID pgtype.UUID,
		decisionReason *string,
		auditParams db.CreateAuditLogParams,
	) (db.Organization, db.OrganizationMembership, error)

	RejectOrganizationTx(
		ctx context.Context,
		orgID pgtype.UUID,
		reviewerUserID pgtype.UUID,
		decisionReason string,
		reasonCode string,
		auditParams db.CreateAuditLogParams,
	) (db.Organization, error)

	UpdateOrganizationProfile(
		ctx context.Context,
		orgID pgtype.UUID,
		tradeName *string,
		auditParams db.CreateAuditLogParams,
	) (db.Organization, error)

	ListActiveOrganizationMembers(ctx context.Context, params db.ListActiveOrganizationMembersParams) ([]db.ListActiveOrganizationMembersRow, error)
	CountActiveOrganizationMembers(ctx context.Context, params db.CountActiveOrganizationMembersParams) (int64, error)

	ListPublicVerifiedOrganizations(ctx context.Context, params db.ListPublicVerifiedOrganizationsParams) ([]db.ListPublicVerifiedOrganizationsRow, error)
	CountPublicVerifiedOrganizations(ctx context.Context, orgType pgtype.Text) (int64, error)
	GetPublicVerifiedOrganizationByID(ctx context.Context, id pgtype.UUID) (db.GetPublicVerifiedOrganizationByIDRow, error)
	CheckOrganizationConflict(ctx context.Context, domain, country, regNum string) (bool, error)
}

// PgxRepository implements Repository backed by pgxpool.Pool and sqlc.
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

// CheckOrganizationConflict checks if a domain or registration number is already in use.
func (r *PgxRepository) CheckOrganizationConflict(ctx context.Context, domain, country, regNum string) (bool, error) {
	return r.queries.CheckOrganizationConflict(ctx, db.CheckOrganizationConflictParams{
		OfficialDomain:     domain,
		CountryCode:        country,
		RegistrationNumber: regNum,
	})
}

// ApplyOrganizationTx creates organization, inactive applicant admin membership, and audit log atomically.
func (r *PgxRepository) ApplyOrganizationTx(
	ctx context.Context,
	orgParams db.CreateOrganizationParams,
	applicantUserID pgtype.UUID,
	applicantRole string,
	auditParams db.CreateAuditLogParams,
) (db.Organization, db.OrganizationMembership, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return db.Organization{}, db.OrganizationMembership{}, err
	}
	defer tx.Rollback(ctx)

	qtx := r.queries.WithTx(tx)

	// Preflight conflict check inside transaction
	hasConflict, err := qtx.CheckOrganizationConflict(ctx, db.CheckOrganizationConflictParams{
		OfficialDomain:     orgParams.OfficialDomain,
		CountryCode:        orgParams.CountryCode,
		RegistrationNumber: orgParams.RegistrationNumber,
	})
	if err != nil {
		return db.Organization{}, db.OrganizationMembership{}, err
	}
	if hasConflict {
		return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeOrganizationAlreadyExists, "An organization with this official domain or registration number already exists")
	}

	// Insert organization
	org, err := qtx.CreateOrganization(ctx, orgParams)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeOrganizationAlreadyExists, "An organization with this official domain or registration number already exists")
		}
		return db.Organization{}, db.OrganizationMembership{}, err
	}

	// Insert pending inactive admin membership
	membership, err := qtx.CreatePendingOrganizationAdminMembership(ctx, db.CreatePendingOrganizationAdminMembershipParams{
		OrganizationID: org.ID,
		UserID:         applicantUserID,
		Role:           applicantRole,
	})
	if err != nil {
		return db.Organization{}, db.OrganizationMembership{}, err
	}

	// Insert audit record
	auditParams.TargetOrganizationID = org.ID
	auditParams.ResourceID = org.ID
	if _, err := qtx.CreateAuditLog(ctx, auditParams); err != nil {
		return db.Organization{}, db.OrganizationMembership{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return db.Organization{}, db.OrganizationMembership{}, err
	}

	return org, membership, nil
}

func (r *PgxRepository) GetOrganizationByID(ctx context.Context, id pgtype.UUID) (db.Organization, error) {
	return r.queries.GetOrganizationByID(ctx, id)
}

func (r *PgxRepository) ListOrganizationsByUserID(ctx context.Context, userID pgtype.UUID) ([]db.ListOrganizationsByUserIDRow, error) {
	return r.queries.ListOrganizationsByUserID(ctx, userID)
}

func (r *PgxRepository) ListOrganizationsFiltered(ctx context.Context, params db.ListOrganizationsFilteredParams) ([]db.Organization, error) {
	return r.queries.ListOrganizationsFiltered(ctx, params)
}

func (r *PgxRepository) CountOrganizationsFiltered(ctx context.Context, params db.CountOrganizationsFilteredParams) (int64, error) {
	return r.queries.CountOrganizationsFiltered(ctx, params)
}

func (r *PgxRepository) GetOrganizationApplicationForAdmin(ctx context.Context, orgID pgtype.UUID) (db.Organization, []db.ListMembershipsByOrgIDWithUserRow, error) {
	org, err := r.queries.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return db.Organization{}, nil, err
	}

	members, err := r.queries.ListMembershipsByOrgIDWithUser(ctx, orgID)
	if err != nil {
		return db.Organization{}, nil, err
	}

	return org, members, nil
}

func (r *PgxRepository) ApproveOrganizationTx(
	ctx context.Context,
	orgID pgtype.UUID,
	reviewerUserID pgtype.UUID,
	decisionReason *string,
	auditParams db.CreateAuditLogParams,
) (db.Organization, db.OrganizationMembership, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return db.Organization{}, db.OrganizationMembership{}, err
	}
	defer tx.Rollback(ctx)

	qtx := r.queries.WithTx(tx)

	// Step 1: Lock organization record without status filter
	org, err := qtx.GetOrganizationForReview(ctx, orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeOrganizationNotFound, "Organization not found")
		}
		return db.Organization{}, db.OrganizationMembership{}, err
	}

	// Step 2: In-transaction state classification
	if org.VerificationStatus != "PENDING" {
		return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeOrganizationNotPending, "Organization is not pending review")
	}

	// Step 3: Lock all memberships for the organization
	memberships, err := qtx.ListMembershipsByOrgIDForReview(ctx, orgID)
	if err != nil {
		return db.Organization{}, db.OrganizationMembership{}, err
	}

	// Step 4: Validate single applicant membership invariant
	if len(memberships) != 1 {
		return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeOrganizationMembershipIntegrityViolation, "Application must contain exactly one applicant membership")
	}

	applicantMembership := memberships[0]
	if applicantMembership.IsActive {
		return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeInvalidMembershipState, "Applicant membership is already active")
	}

	// Step 5: Validate expected admin role matching org type
	var expectedRole string
	switch org.OrgType {
	case "UNIVERSITY":
		expectedRole = "UNIVERSITY_ADMIN"
	case "COMPANY":
		expectedRole = "COMPANY_ADMIN"
	default:
		return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeInvalidMembershipRole, "Unknown organization type")
	}

	if applicantMembership.Role != expectedRole {
		return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeInvalidMembershipRole, "Applicant membership role does not match organization type")
	}

	// Step 6: Anti-self-review guard
	if applicantMembership.UserID == reviewerUserID {
		return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeOrganizationSelfReviewProhibited, "Superadmins cannot approve an application they submitted")
	}

	// Step 7: Conditional transition to VERIFIED (hard-coded in SQL)
	var reasonText pgtype.Text
	if decisionReason != nil && *decisionReason != "" {
		reasonText = pgtype.Text{String: *decisionReason, Valid: true}
	}

	reviewedOrg, err := qtx.ApproveOrganizationIfPending(ctx, db.ApproveOrganizationIfPendingParams{
		ID:               orgID,
		ReviewedByUserID: reviewerUserID,
		DecisionReason:   reasonText,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeOrganizationNotPending, "Organization is no longer pending review")
		}
		return db.Organization{}, db.OrganizationMembership{}, err
	}

	// Step 8: Activate only the exact applicant membership
	activatedMembership, err := qtx.ActivateOrganizationAdminMembership(ctx, db.ActivateOrganizationAdminMembershipParams{
		ID:             applicantMembership.ID,
		OrganizationID: orgID,
		UserID:         applicantMembership.UserID,
		Role:           expectedRole,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeInvalidMembershipState, "Failed to activate applicant membership")
		}
		return db.Organization{}, db.OrganizationMembership{}, err
	}

	// Step 9: Insert minimal audit record
	auditParams.TargetOrganizationID = orgID
	auditParams.ResourceID = orgID
	if _, err := qtx.CreateAuditLog(ctx, auditParams); err != nil {
		return db.Organization{}, db.OrganizationMembership{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return db.Organization{}, db.OrganizationMembership{}, err
	}

	return reviewedOrg, activatedMembership, nil
}

func (r *PgxRepository) RejectOrganizationTx(
	ctx context.Context,
	orgID pgtype.UUID,
	reviewerUserID pgtype.UUID,
	decisionReason string,
	reasonCode string,
	auditParams db.CreateAuditLogParams,
) (db.Organization, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return db.Organization{}, err
	}
	defer tx.Rollback(ctx)

	qtx := r.queries.WithTx(tx)

	// Step 1: Lock organization record without status filter
	org, err := qtx.GetOrganizationForReview(ctx, orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Organization{}, core.NewAppError(core.ErrCodeOrganizationNotFound, "Organization not found")
		}
		return db.Organization{}, err
	}

	// Step 2: In-transaction state classification
	if org.VerificationStatus != "PENDING" {
		return db.Organization{}, core.NewAppError(core.ErrCodeOrganizationNotPending, "Organization is not pending review")
	}

	// Step 3: Lock memberships to resolve applicant user ID
	memberships, err := qtx.ListMembershipsByOrgIDForReview(ctx, orgID)
	if err != nil {
		return db.Organization{}, err
	}

	if len(memberships) != 1 {
		return db.Organization{}, core.NewAppError(core.ErrCodeOrganizationMembershipIntegrityViolation, "Application must contain exactly one applicant membership")
	}

	// Step 4: Anti-self-review guard
	if memberships[0].UserID == reviewerUserID {
		return db.Organization{}, core.NewAppError(core.ErrCodeOrganizationSelfReviewProhibited, "Superadmins cannot reject an application they submitted")
	}

	// Step 5: Conditional transition to REJECTED (hard-coded in SQL)
	rejectedOrg, err := qtx.RejectOrganizationIfPending(ctx, db.RejectOrganizationIfPendingParams{
		ID:               orgID,
		ReviewedByUserID: reviewerUserID,
		DecisionReason:   pgtype.Text{String: decisionReason, Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Organization{}, core.NewAppError(core.ErrCodeOrganizationNotPending, "Organization is no longer pending review")
		}
		return db.Organization{}, err
	}

	// Step 6: Membership remains inactive (no activation query executed)

	// Step 7: Insert minimal audit record
	auditParams.TargetOrganizationID = orgID
	auditParams.ResourceID = orgID
	if _, err := qtx.CreateAuditLog(ctx, auditParams); err != nil {
		return db.Organization{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return db.Organization{}, err
	}

	return rejectedOrg, nil
}

func (r *PgxRepository) UpdateOrganizationProfile(
	ctx context.Context,
	orgID pgtype.UUID,
	tradeName *string,
	auditParams db.CreateAuditLogParams,
) (db.Organization, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return db.Organization{}, err
	}
	defer tx.Rollback(ctx)

	qtx := r.queries.WithTx(tx)

	var tradeNameText pgtype.Text
	if tradeName != nil && *tradeName != "" {
		tradeNameText = pgtype.Text{String: *tradeName, Valid: true}
	}

	org, err := qtx.UpdateOrganizationProfile(ctx, db.UpdateOrganizationProfileParams{
		ID:        orgID,
		TradeName: tradeNameText,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Organization{}, core.NewAppError(core.ErrCodeOrganizationNotFound, "Organization not found or not active")
		}
		return db.Organization{}, err
	}

	auditParams.TargetOrganizationID = orgID
	auditParams.ResourceID = orgID
	if _, err := qtx.CreateAuditLog(ctx, auditParams); err != nil {
		return db.Organization{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return db.Organization{}, err
	}

	return org, nil
}

func (r *PgxRepository) ListActiveOrganizationMembers(ctx context.Context, params db.ListActiveOrganizationMembersParams) ([]db.ListActiveOrganizationMembersRow, error) {
	return r.queries.ListActiveOrganizationMembers(ctx, params)
}

func (r *PgxRepository) CountActiveOrganizationMembers(ctx context.Context, params db.CountActiveOrganizationMembersParams) (int64, error) {
	return r.queries.CountActiveOrganizationMembers(ctx, params)
}

func (r *PgxRepository) ListPublicVerifiedOrganizations(ctx context.Context, params db.ListPublicVerifiedOrganizationsParams) ([]db.ListPublicVerifiedOrganizationsRow, error) {
	return r.queries.ListPublicVerifiedOrganizations(ctx, params)
}

func (r *PgxRepository) CountPublicVerifiedOrganizations(ctx context.Context, orgType pgtype.Text) (int64, error) {
	return r.queries.CountPublicVerifiedOrganizations(ctx, orgType)
}

func (r *PgxRepository) GetPublicVerifiedOrganizationByID(ctx context.Context, id pgtype.UUID) (db.GetPublicVerifiedOrganizationByIDRow, error) {
	return r.queries.GetPublicVerifiedOrganizationByID(ctx, id)
}
