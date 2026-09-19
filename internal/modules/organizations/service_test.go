package organizations

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

var (
	testOrgUUID1    = pgtype.UUID{Bytes: [16]byte{0x10, 0x01}, Valid: true}
	testUserUUID1   = pgtype.UUID{Bytes: [16]byte{0x20, 0x01}, Valid: true}
	testUserUUID2   = pgtype.UUID{Bytes: [16]byte{0x20, 0x02}, Valid: true}
	testMemberUUID1 = pgtype.UUID{Bytes: [16]byte{0x30, 0x01}, Valid: true}
)

func TestService_ApplyOrganization_UniversitySuccess(t *testing.T) {
	mockRepo := &mockRepository{
		applyOrgTxFn: func(ctx context.Context, orgParams db.CreateOrganizationParams, applicantUserID pgtype.UUID, applicantRole string, auditParams db.CreateAuditLogParams) (db.Organization, db.OrganizationMembership, error) {
			if applicantRole != "UNIVERSITY_ADMIN" {
				t.Fatalf("expected role UNIVERSITY_ADMIN, got %s", applicantRole)
			}
			if orgParams.CountryCode != "US" {
				t.Fatalf("expected country_code US, got %s", orgParams.CountryCode)
			}
			if orgParams.RegistrationNumber != "REG123" {
				t.Fatalf("expected reg number REG123, got %s", orgParams.RegistrationNumber)
			}
			if orgParams.OfficialDomain != "harvard.edu" {
				t.Fatalf("expected domain harvard.edu, got %s", orgParams.OfficialDomain)
			}

			// Verify minimal audit payload
			var payload map[string]interface{}
			if err := json.Unmarshal(auditParams.Payload, &payload); err != nil {
				t.Fatalf("failed to parse audit payload: %v", err)
			}
			if payload["org_type"] != "UNIVERSITY" {
				t.Fatalf("expected audit org_type UNIVERSITY, got %v", payload["org_type"])
			}
			if _, exists := payload["legal_name"]; exists {
				t.Fatalf("audit payload must not contain legal_name")
			}
			if _, exists := payload["official_domain"]; exists {
				t.Fatalf("audit payload must not contain official_domain")
			}

			return db.Organization{
					ID:                 testOrgUUID1,
					OrgType:            "UNIVERSITY",
					LegalName:          orgParams.LegalName,
					CountryCode:        "US",
					RegistrationNumber: "REG123",
					OfficialDomain:     "harvard.edu",
					VerificationStatus: "PENDING",
				}, db.OrganizationMembership{
					ID:             testMemberUUID1,
					OrganizationID: testOrgUUID1,
					UserID:         applicantUserID,
					Role:           applicantRole,
					IsActive:       false,
				}, nil
		},
	}

	svc := NewService(mockRepo)
	applicant := db.User{ID: testUserUUID1, Email: "admin@harvard.edu", IsSuperadmin: false}

	tradeName := "Harvard"
	req := ApplyOrganizationRequest{
		OrgType:            "UNIVERSITY",
		LegalName:          "President and Fellows of Harvard College",
		TradeName:          &tradeName,
		CountryCode:        "us ",
		RegistrationNumber: "reg123 ",
		OfficialDomain:     "HARVARD.EDU ",
	}

	resp, err := svc.ApplyOrganization(context.Background(), req, applicant, net.ParseIP("127.0.0.1"), "test-agent")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if resp.Organization.VerificationStatus != "PENDING" {
		t.Fatalf("expected PENDING status, got %s", resp.Organization.VerificationStatus)
	}
	if resp.Membership.IsActive != false {
		t.Fatalf("expected membership to be inactive, got active")
	}
	if resp.Membership.Role != "UNIVERSITY_ADMIN" {
		t.Fatalf("expected role UNIVERSITY_ADMIN, got %s", resp.Membership.Role)
	}
}

func TestService_ApplyOrganization_CompanySuccess(t *testing.T) {
	mockRepo := &mockRepository{
		applyOrgTxFn: func(ctx context.Context, orgParams db.CreateOrganizationParams, applicantUserID pgtype.UUID, applicantRole string, auditParams db.CreateAuditLogParams) (db.Organization, db.OrganizationMembership, error) {
			if applicantRole != "COMPANY_ADMIN" {
				t.Fatalf("expected role COMPANY_ADMIN, got %s", applicantRole)
			}
			return db.Organization{
					ID:                 testOrgUUID1,
					OrgType:            "COMPANY",
					LegalName:          orgParams.LegalName,
					CountryCode:        "GB",
					RegistrationNumber: "CO12345",
					OfficialDomain:     "techcorp.co.uk",
					VerificationStatus: "PENDING",
				}, db.OrganizationMembership{
					ID:             testMemberUUID1,
					OrganizationID: testOrgUUID1,
					UserID:         applicantUserID,
					Role:           applicantRole,
					IsActive:       false,
				}, nil
		},
	}

	svc := NewService(mockRepo)
	applicant := db.User{ID: testUserUUID1, Email: "hr@techcorp.co.uk"}
	req := ApplyOrganizationRequest{
		OrgType:            "COMPANY",
		LegalName:          "Tech Corp Limited",
		CountryCode:        "GB",
		RegistrationNumber: "CO12345",
		OfficialDomain:     "techcorp.co.uk",
	}

	resp, err := svc.ApplyOrganization(context.Background(), req, applicant, nil, "")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if resp.Organization.OrgType != "COMPANY" {
		t.Fatalf("expected org_type COMPANY, got %s", resp.Organization.OrgType)
	}
	if resp.Membership.Role != "COMPANY_ADMIN" {
		t.Fatalf("expected role COMPANY_ADMIN, got %s", resp.Membership.Role)
	}
}

func TestService_ApplyOrganization_ValidationErrors(t *testing.T) {
	svc := NewService(&mockRepository{})
	applicant := db.User{ID: testUserUUID1}

	// 1. Invalid org type
	req1 := ApplyOrganizationRequest{
		OrgType:            "INVALID_TYPE",
		LegalName:          "Legal Entity",
		CountryCode:        "US",
		RegistrationNumber: "123",
		OfficialDomain:     "example.com",
	}
	if _, err := svc.ApplyOrganization(context.Background(), req1, applicant, nil, ""); err == nil {
		t.Fatal("expected error for invalid org type")
	}

	// 2. Invalid country code (not 2 uppercase alpha)
	req2 := ApplyOrganizationRequest{
		OrgType:            "UNIVERSITY",
		LegalName:          "Legal Entity",
		CountryCode:        "USA",
		RegistrationNumber: "123",
		OfficialDomain:     "example.com",
	}
	if _, err := svc.ApplyOrganization(context.Background(), req2, applicant, nil, ""); err == nil {
		t.Fatal("expected error for invalid country code")
	}

	// 3. Invalid domain format (protocol included)
	req3 := ApplyOrganizationRequest{
		OrgType:            "UNIVERSITY",
		LegalName:          "Legal Entity",
		CountryCode:        "US",
		RegistrationNumber: "123",
		OfficialDomain:     "https://example.com",
	}
	if _, err := svc.ApplyOrganization(context.Background(), req3, applicant, nil, ""); err == nil {
		t.Fatal("expected error for domain with protocol")
	}

	// 4. Duplicate conflict from repository
	mockRepoConflict := &mockRepository{
		applyOrgTxFn: func(ctx context.Context, orgParams db.CreateOrganizationParams, applicantUserID pgtype.UUID, applicantRole string, auditParams db.CreateAuditLogParams) (db.Organization, db.OrganizationMembership, error) {
			return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeOrganizationAlreadyExists, "conflict")
		},
	}
	svcConflict := NewService(mockRepoConflict)
	req4 := ApplyOrganizationRequest{
		OrgType:            "UNIVERSITY",
		LegalName:          "Legal Entity",
		CountryCode:        "US",
		RegistrationNumber: "123",
		OfficialDomain:     "example.com",
	}
	_, err := svcConflict.ApplyOrganization(context.Background(), req4, applicant, nil, "")
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeOrganizationAlreadyExists {
		t.Fatalf("expected ORGANIZATION_ALREADY_EXISTS, got %v", err)
	}
}

func TestService_ListMyOrganizations(t *testing.T) {
	mockRepo := &mockRepository{
		listOrgsByUserIDFn: func(ctx context.Context, userID pgtype.UUID) ([]db.ListOrganizationsByUserIDRow, error) {
			return []db.ListOrganizationsByUserIDRow{
				{
					ID:                 testOrgUUID1,
					OrgType:            "UNIVERSITY",
					LegalName:          "Pending Uni",
					CountryCode:        "US",
					RegistrationNumber: "REG1",
					OfficialDomain:     "uni.edu",
					VerificationStatus: "PENDING",
					UserRole:           "UNIVERSITY_ADMIN",
					UserIsActive:       false,
				},
				{
					ID:                 testOrgUUID1,
					OrgType:            "COMPANY",
					LegalName:          "Rejected Co",
					CountryCode:        "US",
					RegistrationNumber: "REG2",
					OfficialDomain:     "co.com",
					VerificationStatus: "REJECTED",
					DecisionReason:     pgtype.Text{String: "Invalid documents", Valid: true},
					UserRole:           "COMPANY_ADMIN",
					UserIsActive:       false,
				},
			}, nil
		},
	}

	svc := NewService(mockRepo)
	orgs, err := svc.ListMyOrganizations(context.Background(), testUserUUID1)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if len(orgs) != 2 {
		t.Fatalf("expected 2 orgs, got %d", len(orgs))
	}
	// Verify decision reason is exposed on REJECTED org
	if orgs[1].DecisionReason == nil || *orgs[1].DecisionReason != "Invalid documents" {
		t.Fatalf("expected decision reason on rejected org")
	}
	// Verify decision reason is nil on PENDING org
	if orgs[0].DecisionReason != nil {
		t.Fatalf("expected nil decision reason on pending org")
	}
}

func TestService_ApproveOrganization_Success(t *testing.T) {
	mockRepo := &mockRepository{
		approveOrgTxFn: func(ctx context.Context, orgID pgtype.UUID, reviewerUserID pgtype.UUID, decisionReason *string, auditParams db.CreateAuditLogParams) (db.Organization, db.OrganizationMembership, error) {
			return db.Organization{
					ID:                 orgID,
					OrgType:            "UNIVERSITY",
					LegalName:          "Approved University",
					VerificationStatus: "VERIFIED",
					ReviewedByUserID:   reviewerUserID,
				}, db.OrganizationMembership{
					ID:             testMemberUUID1,
					OrganizationID: orgID,
					UserID:         testUserUUID1,
					Role:           "UNIVERSITY_ADMIN",
					IsActive:       true,
				}, nil
		},
	}

	svc := NewService(mockRepo)
	reviewer := db.User{ID: testUserUUID2, IsSuperadmin: true}

	reason := "Accreditation verified"
	req := ApproveOrganizationRequest{Reason: &reason}

	org, member, err := svc.ApproveOrganization(context.Background(), testOrgUUID1, req, reviewer, nil, "")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if org.VerificationStatus != "VERIFIED" {
		t.Fatalf("expected VERIFIED, got %s", org.VerificationStatus)
	}
	if !member.IsActive {
		t.Fatalf("expected activated membership to be true")
	}
}

func TestService_ApproveOrganization_Errors(t *testing.T) {
	// 1. Anti-self-review error
	mockRepoSelfReview := &mockRepository{
		approveOrgTxFn: func(ctx context.Context, orgID pgtype.UUID, reviewerUserID pgtype.UUID, decisionReason *string, auditParams db.CreateAuditLogParams) (db.Organization, db.OrganizationMembership, error) {
			return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeOrganizationSelfReviewProhibited, "self review")
		},
	}
	svcSelf := NewService(mockRepoSelfReview)
	_, _, err := svcSelf.ApproveOrganization(context.Background(), testOrgUUID1, ApproveOrganizationRequest{}, db.User{ID: testUserUUID1}, nil, "")
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeOrganizationSelfReviewProhibited {
		t.Fatalf("expected ORGANIZATION_SELF_REVIEW_PROHIBITED, got %v", err)
	}

	// 2. Non-pending conflict error
	mockRepoNotPending := &mockRepository{
		approveOrgTxFn: func(ctx context.Context, orgID pgtype.UUID, reviewerUserID pgtype.UUID, decisionReason *string, auditParams db.CreateAuditLogParams) (db.Organization, db.OrganizationMembership, error) {
			return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeOrganizationNotPending, "not pending")
		},
	}
	svcNotPending := NewService(mockRepoNotPending)
	_, _, err = svcNotPending.ApproveOrganization(context.Background(), testOrgUUID1, ApproveOrganizationRequest{}, db.User{ID: testUserUUID2}, nil, "")
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeOrganizationNotPending {
		t.Fatalf("expected ORGANIZATION_NOT_PENDING, got %v", err)
	}

	// 3. Organization not found (404)
	mockRepoNotFound := &mockRepository{
		approveOrgTxFn: func(ctx context.Context, orgID pgtype.UUID, reviewerUserID pgtype.UUID, decisionReason *string, auditParams db.CreateAuditLogParams) (db.Organization, db.OrganizationMembership, error) {
			return db.Organization{}, db.OrganizationMembership{}, core.NewAppError(core.ErrCodeOrganizationNotFound, "not found")
		},
	}
	svcNotFound := NewService(mockRepoNotFound)
	_, _, err = svcNotFound.ApproveOrganization(context.Background(), testOrgUUID1, ApproveOrganizationRequest{}, db.User{ID: testUserUUID2}, nil, "")
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeOrganizationNotFound {
		t.Fatalf("expected ORGANIZATION_NOT_FOUND, got %v", err)
	}
}

func TestService_RejectOrganization_SuccessAndAuditValidation(t *testing.T) {
	mockRepo := &mockRepository{
		rejectOrgTxFn: func(ctx context.Context, orgID pgtype.UUID, reviewerUserID pgtype.UUID, decisionReason string, reasonCode string, auditParams db.CreateAuditLogParams) (db.Organization, error) {
			// Verify free-text reason is NOT in audit payload
			var payload map[string]interface{}
			if err := json.Unmarshal(auditParams.Payload, &payload); err != nil {
				t.Fatalf("failed to unmarshal audit payload: %v", err)
			}
			if _, exists := payload["decision_reason"]; exists {
				t.Fatalf("decision_reason free text must not be stored in audit payload")
			}
			if payload["reason_code"] != ReasonCodeRegistrationNotVerified {
				t.Fatalf("expected reason_code %s, got %v", ReasonCodeRegistrationNotVerified, payload["reason_code"])
			}
			if payload["new_status"] != "REJECTED" {
				t.Fatalf("expected new_status REJECTED")
			}

			return db.Organization{
				ID:                 orgID,
				VerificationStatus: "REJECTED",
				ReviewedByUserID:   reviewerUserID,
				DecisionReason:     pgtype.Text{String: decisionReason, Valid: true},
			}, nil
		},
	}

	svc := NewService(mockRepo)
	reviewer := db.User{ID: testUserUUID2, IsSuperadmin: true}

	req := RejectOrganizationRequest{
		DecisionReason: "Tax registration number cannot be found in national database.",
		ReasonCode:     ReasonCodeRegistrationNotVerified,
	}

	org, err := svc.RejectOrganization(context.Background(), testOrgUUID1, req, reviewer, nil, "")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if org.VerificationStatus != "REJECTED" {
		t.Fatalf("expected REJECTED, got %s", org.VerificationStatus)
	}
}

func TestService_RejectOrganization_ReasonValidation(t *testing.T) {
	svc := NewService(&mockRepository{})
	reviewer := db.User{ID: testUserUUID2}

	// 1. Missing / too short decision_reason
	req1 := RejectOrganizationRequest{
		DecisionReason: "bad",
		ReasonCode:     ReasonCodeRegistrationNotVerified,
	}
	_, err := svc.RejectOrganization(context.Background(), testOrgUUID1, req1, reviewer, nil, "")
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeDecisionReasonRequired {
		t.Fatalf("expected DECISION_REASON_REQUIRED, got %v", err)
	}

	// 2. Invalid reason_code
	req2 := RejectOrganizationRequest{
		DecisionReason: "Proper explanation for the rejection.",
		ReasonCode:     "INVALID_REASON_CODE",
	}
	_, err = svc.RejectOrganization(context.Background(), testOrgUUID1, req2, reviewer, nil, "")
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeInvalidReasonCode {
		t.Fatalf("expected INVALID_REASON_CODE, got %v", err)
	}
}

func TestService_UpdateOrganizationProfile(t *testing.T) {
	mockRepo := &mockRepository{
		updateOrgProfileFn: func(ctx context.Context, orgID pgtype.UUID, tradeName *string, auditParams db.CreateAuditLogParams) (db.Organization, error) {
			return db.Organization{
				ID:                 orgID,
				TradeName:          pgtype.Text{String: *tradeName, Valid: true},
				VerificationStatus: "VERIFIED",
			}, nil
		},
	}

	svc := NewService(mockRepo)
	newTradeName := "Updated Trade Name"
	req := UpdateOrganizationProfileRequest{TradeName: &newTradeName}

	org, err := svc.UpdateOrganizationProfile(context.Background(), testOrgUUID1, req, testUserUUID1, nil, "")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if org.TradeName == nil || *org.TradeName != newTradeName {
		t.Fatalf("expected %s, got %v", newTradeName, org.TradeName)
	}
}

func TestService_ListOrganizationMembers_PaginationAndFilters(t *testing.T) {
	mockRepo := &mockRepository{
		countActiveMembersFn: func(ctx context.Context, params db.CountActiveOrganizationMembersParams) (int64, error) {
			return 1, nil
		},
		listActiveMembersFn: func(ctx context.Context, params db.ListActiveOrganizationMembersParams) ([]db.ListActiveOrganizationMembersRow, error) {
			return []db.ListActiveOrganizationMembersRow{
				{
					ID:           testMemberUUID1,
					UserID:       testUserUUID1,
					Role:         "UNIVERSITY_ADMIN",
					IsActive:     true,
					UserFullName: "Admin User",
					UserEmail:    "admin@uni.edu",
				},
			}, nil
		},
	}

	svc := NewService(mockRepo)

	// Valid role
	members, pag, err := svc.ListOrganizationMembers(context.Background(), testOrgUUID1, "UNIVERSITY_ADMIN", 1, 20)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if len(members) != 1 || pag.TotalRecords != 1 {
		t.Fatalf("expected 1 member, got %d", len(members))
	}

	// Invalid role filter
	_, _, err = svc.ListOrganizationMembers(context.Background(), testOrgUUID1, "INVALID_ROLE", 1, 20)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeInvalidFilterParam {
		t.Fatalf("expected INVALID_FILTER_PARAM, got %v", err)
	}
}

func TestService_PublicVerifiedOrganization_SafeProjectionAnd404(t *testing.T) {
	mockRepo := &mockRepository{
		getPublicVerifiedOrgByIDFn: func(ctx context.Context, id pgtype.UUID) (db.GetPublicVerifiedOrganizationByIDRow, error) {
			if id == testOrgUUID1 {
				return db.GetPublicVerifiedOrganizationByIDRow{
					ID:             testOrgUUID1,
					OrgType:        "UNIVERSITY",
					LegalName:      "Public Uni",
					CountryCode:    "US",
					OfficialDomain: "pub.edu",
				}, nil
			}
			return db.GetPublicVerifiedOrganizationByIDRow{}, pgx.ErrNoRows
		},
	}

	svc := NewService(mockRepo)

	// 1. Exists & Verified -> 200 safe projection
	org, err := svc.GetPublicVerifiedOrganization(context.Background(), testOrgUUID1)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if org.LegalName != "Public Uni" {
		t.Fatalf("expected Public Uni, got %s", org.LegalName)
	}

	// 2. Non-existent or non-verified -> identical 404
	_, err = svc.GetPublicVerifiedOrganization(context.Background(), pgtype.UUID{Bytes: [16]byte{0x99}})
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCodeOrganizationNotFound {
		t.Fatalf("expected ORGANIZATION_NOT_FOUND, got %v", err)
	}
}
