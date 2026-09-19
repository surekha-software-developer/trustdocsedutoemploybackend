package organizations

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

type mockService struct {
	Service
	applyOrgFn               func(ctx context.Context, req ApplyOrganizationRequest, applicantUser db.User, clientIP net.IP, userAgent string) (*ApplicantSubmissionResponse, error)
	listMyOrgsFn             func(ctx context.Context, userID pgtype.UUID) ([]MyOrganizationResponse, error)
	getTenantOrgFn           func(ctx context.Context, orgID pgtype.UUID) (*OrganizationResponse, error)
	updateProfileFn          func(ctx context.Context, orgID pgtype.UUID, req UpdateOrganizationProfileRequest, actorUserID pgtype.UUID, clientIP net.IP, userAgent string) (*OrganizationResponse, error)
	listMembersFn            func(ctx context.Context, orgID pgtype.UUID, roleFilter string, page, limit int) ([]MemberResponse, *PaginationResponse, error)
	listOrgsAdminFn          func(ctx context.Context, statusFilter, typeFilter string, page, limit int) ([]OrganizationResponse, *PaginationResponse, error)
	getAdminDossierFn        func(ctx context.Context, orgID pgtype.UUID) (*AdminDossierResponse, error)
	approveOrgFn             func(ctx context.Context, orgID pgtype.UUID, req ApproveOrganizationRequest, reviewerUser db.User, clientIP net.IP, userAgent string) (*OrganizationResponse, *MembershipSummaryResponse, error)
	rejectOrgFn              func(ctx context.Context, orgID pgtype.UUID, req RejectOrganizationRequest, reviewerUser db.User, clientIP net.IP, userAgent string) (*OrganizationResponse, error)
	listPublicVerifiedOrgsFn func(ctx context.Context, typeFilter string, page, limit int) ([]PublicVerifiedOrganizationResponse, *PaginationResponse, error)
	getPublicVerifiedOrgFn   func(ctx context.Context, orgID pgtype.UUID) (*PublicVerifiedOrganizationResponse, error)
}

func (m *mockService) ApplyOrganization(ctx context.Context, req ApplyOrganizationRequest, applicantUser db.User, clientIP net.IP, userAgent string) (*ApplicantSubmissionResponse, error) {
	if m.applyOrgFn != nil {
		return m.applyOrgFn(ctx, req, applicantUser, clientIP, userAgent)
	}
	return nil, nil
}

func (m *mockService) ListMyOrganizations(ctx context.Context, userID pgtype.UUID) ([]MyOrganizationResponse, error) {
	if m.listMyOrgsFn != nil {
		return m.listMyOrgsFn(ctx, userID)
	}
	return nil, nil
}

func (m *mockService) GetTenantOrganization(ctx context.Context, orgID pgtype.UUID) (*OrganizationResponse, error) {
	if m.getTenantOrgFn != nil {
		return m.getTenantOrgFn(ctx, orgID)
	}
	return nil, nil
}

func (m *mockService) UpdateOrganizationProfile(ctx context.Context, orgID pgtype.UUID, req UpdateOrganizationProfileRequest, actorUserID pgtype.UUID, clientIP net.IP, userAgent string) (*OrganizationResponse, error) {
	if m.updateProfileFn != nil {
		return m.updateProfileFn(ctx, orgID, req, actorUserID, clientIP, userAgent)
	}
	return nil, nil
}

func (m *mockService) ListOrganizationMembers(ctx context.Context, orgID pgtype.UUID, roleFilter string, page, limit int) ([]MemberResponse, *PaginationResponse, error) {
	if m.listMembersFn != nil {
		return m.listMembersFn(ctx, orgID, roleFilter, page, limit)
	}
	return nil, nil, nil
}

func (m *mockService) ListOrganizationsAdmin(ctx context.Context, statusFilter, typeFilter string, page, limit int) ([]OrganizationResponse, *PaginationResponse, error) {
	if m.listOrgsAdminFn != nil {
		return m.listOrgsAdminFn(ctx, statusFilter, typeFilter, page, limit)
	}
	return nil, nil, nil
}

func (m *mockService) GetOrganizationAdminDossier(ctx context.Context, orgID pgtype.UUID) (*AdminDossierResponse, error) {
	if m.getAdminDossierFn != nil {
		return m.getAdminDossierFn(ctx, orgID)
	}
	return nil, nil
}

func (m *mockService) ApproveOrganization(ctx context.Context, orgID pgtype.UUID, req ApproveOrganizationRequest, reviewerUser db.User, clientIP net.IP, userAgent string) (*OrganizationResponse, *MembershipSummaryResponse, error) {
	if m.approveOrgFn != nil {
		return m.approveOrgFn(ctx, orgID, req, reviewerUser, clientIP, userAgent)
	}
	return nil, nil, nil
}

func (m *mockService) RejectOrganization(ctx context.Context, orgID pgtype.UUID, req RejectOrganizationRequest, reviewerUser db.User, clientIP net.IP, userAgent string) (*OrganizationResponse, error) {
	if m.rejectOrgFn != nil {
		return m.rejectOrgFn(ctx, orgID, req, reviewerUser, clientIP, userAgent)
	}
	return nil, nil
}

func (m *mockService) ListPublicVerifiedOrganizations(ctx context.Context, typeFilter string, page, limit int) ([]PublicVerifiedOrganizationResponse, *PaginationResponse, error) {
	if m.listPublicVerifiedOrgsFn != nil {
		return m.listPublicVerifiedOrgsFn(ctx, typeFilter, page, limit)
	}
	return nil, nil, nil
}

func (m *mockService) GetPublicVerifiedOrganization(ctx context.Context, orgID pgtype.UUID) (*PublicVerifiedOrganizationResponse, error) {
	if m.getPublicVerifiedOrgFn != nil {
		return m.getPublicVerifiedOrgFn(ctx, orgID)
	}
	return nil, nil
}

func TestHandler_ApplyOrganization_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockSvc := &mockService{
		applyOrgFn: func(ctx context.Context, req ApplyOrganizationRequest, applicantUser db.User, clientIP net.IP, userAgent string) (*ApplicantSubmissionResponse, error) {
			return &ApplicantSubmissionResponse{
				Organization: OrganizationResponse{
					ID:                 "10010000-0000-0000-0000-000000000000",
					OrgType:            "UNIVERSITY",
					LegalName:          req.LegalName,
					VerificationStatus: "PENDING",
				},
				Membership: MembershipSummaryResponse{
					ID:       "30010000-0000-0000-0000-000000000000",
					Role:     "UNIVERSITY_ADMIN",
					IsActive: false,
				},
			}, nil
		},
	}

	h := NewHandler(mockSvc)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user", db.User{ID: testUserUUID1})
		c.Next()
	})
	r.POST("/organizations", h.ApplyOrganization)

	body, _ := json.Marshal(ApplyOrganizationRequest{
		OrgType:            "UNIVERSITY",
		LegalName:          "Harvard College",
		CountryCode:        "US",
		RegistrationNumber: "REG123",
		OfficialDomain:     "harvard.edu",
	})

	req, _ := http.NewRequest(http.MethodPost, "/organizations", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_ListOrganizationMembers_Headers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockSvc := &mockService{
		listMembersFn: func(ctx context.Context, orgID pgtype.UUID, roleFilter string, page, limit int) ([]MemberResponse, *PaginationResponse, error) {
			return []MemberResponse{}, &PaginationResponse{Page: 1, Limit: 20, TotalRecords: 0, TotalPages: 1}, nil
		},
	}

	h := NewHandler(mockSvc)
	r := gin.New()
	r.GET("/organizations/:organization_id/members", h.ListOrganizationMembers)

	req, _ := http.NewRequest(http.MethodGet, "/organizations/10010000-0000-0000-0000-000000000000/members", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expected Cache-Control: no-store, got %s", w.Header().Get("Cache-Control"))
	}
	if w.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("expected Pragma: no-cache, got %s", w.Header().Get("Pragma"))
	}
}

func TestHandler_RejectOrganization_InvalidReasonCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockSvc := &mockService{
		rejectOrgFn: func(ctx context.Context, orgID pgtype.UUID, req RejectOrganizationRequest, reviewerUser db.User, clientIP net.IP, userAgent string) (*OrganizationResponse, error) {
			return nil, core.NewAppError(core.ErrCodeInvalidReasonCode, "invalid code")
		},
	}

	h := NewHandler(mockSvc)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user", db.User{ID: testUserUUID2, IsSuperadmin: true})
		c.Next()
	})
	r.POST("/admin/organizations/:organization_id/reject", h.RejectOrganization)

	body, _ := json.Marshal(RejectOrganizationRequest{
		DecisionReason: "Bad reason",
		ReasonCode:     "NOT_A_CODE",
	})
	req, _ := http.NewRequest(http.MethodPost, "/admin/organizations/10010000-0000-0000-0000-000000000000/reject", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
