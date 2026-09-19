package organizations

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
)

type mockRepository struct {
	applyOrgTxFn               func(ctx context.Context, orgParams db.CreateOrganizationParams, applicantUserID pgtype.UUID, applicantRole string, auditParams db.CreateAuditLogParams) (db.Organization, db.OrganizationMembership, error)
	getOrgByIDFn               func(ctx context.Context, id pgtype.UUID) (db.Organization, error)
	listOrgsByUserIDFn         func(ctx context.Context, userID pgtype.UUID) ([]db.ListOrganizationsByUserIDRow, error)
	listOrgsFilteredFn         func(ctx context.Context, params db.ListOrganizationsFilteredParams) ([]db.Organization, error)
	countOrgsFilteredFn        func(ctx context.Context, params db.CountOrganizationsFilteredParams) (int64, error)
	getOrgAppForAdminFn        func(ctx context.Context, orgID pgtype.UUID) (db.Organization, []db.ListMembershipsByOrgIDWithUserRow, error)
	approveOrgTxFn             func(ctx context.Context, orgID pgtype.UUID, reviewerUserID pgtype.UUID, decisionReason *string, auditParams db.CreateAuditLogParams) (db.Organization, db.OrganizationMembership, error)
	rejectOrgTxFn              func(ctx context.Context, orgID pgtype.UUID, reviewerUserID pgtype.UUID, decisionReason string, reasonCode string, auditParams db.CreateAuditLogParams) (db.Organization, error)
	updateOrgProfileFn         func(ctx context.Context, orgID pgtype.UUID, tradeName *string, auditParams db.CreateAuditLogParams) (db.Organization, error)
	listActiveMembersFn        func(ctx context.Context, params db.ListActiveOrganizationMembersParams) ([]db.ListActiveOrganizationMembersRow, error)
	countActiveMembersFn       func(ctx context.Context, params db.CountActiveOrganizationMembersParams) (int64, error)
	listPublicVerifiedOrgsFn   func(ctx context.Context, params db.ListPublicVerifiedOrganizationsParams) ([]db.ListPublicVerifiedOrganizationsRow, error)
	countPublicVerifiedOrgsFn  func(ctx context.Context, orgType pgtype.Text) (int64, error)
	getPublicVerifiedOrgByIDFn func(ctx context.Context, id pgtype.UUID) (db.GetPublicVerifiedOrganizationByIDRow, error)
	checkOrgConflictFn         func(ctx context.Context, domain, country, regNum string) (bool, error)
}

func (m *mockRepository) ApplyOrganizationTx(ctx context.Context, orgParams db.CreateOrganizationParams, applicantUserID pgtype.UUID, applicantRole string, auditParams db.CreateAuditLogParams) (db.Organization, db.OrganizationMembership, error) {
	if m.applyOrgTxFn != nil {
		return m.applyOrgTxFn(ctx, orgParams, applicantUserID, applicantRole, auditParams)
	}
	return db.Organization{}, db.OrganizationMembership{}, nil
}

func (m *mockRepository) GetOrganizationByID(ctx context.Context, id pgtype.UUID) (db.Organization, error) {
	if m.getOrgByIDFn != nil {
		return m.getOrgByIDFn(ctx, id)
	}
	return db.Organization{}, nil
}

func (m *mockRepository) ListOrganizationsByUserID(ctx context.Context, userID pgtype.UUID) ([]db.ListOrganizationsByUserIDRow, error) {
	if m.listOrgsByUserIDFn != nil {
		return m.listOrgsByUserIDFn(ctx, userID)
	}
	return nil, nil
}

func (m *mockRepository) ListOrganizationsFiltered(ctx context.Context, params db.ListOrganizationsFilteredParams) ([]db.Organization, error) {
	if m.listOrgsFilteredFn != nil {
		return m.listOrgsFilteredFn(ctx, params)
	}
	return nil, nil
}

func (m *mockRepository) CountOrganizationsFiltered(ctx context.Context, params db.CountOrganizationsFilteredParams) (int64, error) {
	if m.countOrgsFilteredFn != nil {
		return m.countOrgsFilteredFn(ctx, params)
	}
	return 0, nil
}

func (m *mockRepository) GetOrganizationApplicationForAdmin(ctx context.Context, orgID pgtype.UUID) (db.Organization, []db.ListMembershipsByOrgIDWithUserRow, error) {
	if m.getOrgAppForAdminFn != nil {
		return m.getOrgAppForAdminFn(ctx, orgID)
	}
	return db.Organization{}, nil, nil
}

func (m *mockRepository) ApproveOrganizationTx(ctx context.Context, orgID pgtype.UUID, reviewerUserID pgtype.UUID, decisionReason *string, auditParams db.CreateAuditLogParams) (db.Organization, db.OrganizationMembership, error) {
	if m.approveOrgTxFn != nil {
		return m.approveOrgTxFn(ctx, orgID, reviewerUserID, decisionReason, auditParams)
	}
	return db.Organization{}, db.OrganizationMembership{}, nil
}

func (m *mockRepository) RejectOrganizationTx(ctx context.Context, orgID pgtype.UUID, reviewerUserID pgtype.UUID, decisionReason string, reasonCode string, auditParams db.CreateAuditLogParams) (db.Organization, error) {
	if m.rejectOrgTxFn != nil {
		return m.rejectOrgTxFn(ctx, orgID, reviewerUserID, decisionReason, reasonCode, auditParams)
	}
	return db.Organization{}, nil
}

func (m *mockRepository) UpdateOrganizationProfile(ctx context.Context, orgID pgtype.UUID, tradeName *string, auditParams db.CreateAuditLogParams) (db.Organization, error) {
	if m.updateOrgProfileFn != nil {
		return m.updateOrgProfileFn(ctx, orgID, tradeName, auditParams)
	}
	return db.Organization{}, nil
}

func (m *mockRepository) ListActiveOrganizationMembers(ctx context.Context, params db.ListActiveOrganizationMembersParams) ([]db.ListActiveOrganizationMembersRow, error) {
	if m.listActiveMembersFn != nil {
		return m.listActiveMembersFn(ctx, params)
	}
	return nil, nil
}

func (m *mockRepository) CountActiveOrganizationMembers(ctx context.Context, params db.CountActiveOrganizationMembersParams) (int64, error) {
	if m.countActiveMembersFn != nil {
		return m.countActiveMembersFn(ctx, params)
	}
	return 0, nil
}

func (m *mockRepository) ListPublicVerifiedOrganizations(ctx context.Context, params db.ListPublicVerifiedOrganizationsParams) ([]db.ListPublicVerifiedOrganizationsRow, error) {
	if m.listPublicVerifiedOrgsFn != nil {
		return m.listPublicVerifiedOrgsFn(ctx, params)
	}
	return nil, nil
}

func (m *mockRepository) CountPublicVerifiedOrganizations(ctx context.Context, orgType pgtype.Text) (int64, error) {
	if m.countPublicVerifiedOrgsFn != nil {
		return m.countPublicVerifiedOrgsFn(ctx, orgType)
	}
	return 0, nil
}

func (m *mockRepository) GetPublicVerifiedOrganizationByID(ctx context.Context, id pgtype.UUID) (db.GetPublicVerifiedOrganizationByIDRow, error) {
	if m.getPublicVerifiedOrgByIDFn != nil {
		return m.getPublicVerifiedOrgByIDFn(ctx, id)
	}
	return db.GetPublicVerifiedOrganizationByIDRow{}, nil
}

func (m *mockRepository) CheckOrganizationConflict(ctx context.Context, domain, country, regNum string) (bool, error) {
	if m.checkOrgConflictFn != nil {
		return m.checkOrgConflictFn(ctx, domain, country, regNum)
	}
	return false, nil
}
