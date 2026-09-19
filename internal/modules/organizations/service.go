package organizations

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

func toNetipAddr(ip net.IP) *netip.Addr {
	if ip == nil {
		return nil
	}
	if addr, ok := netip.AddrFromSlice(ip); ok {
		return &addr
	}
	return nil
}

func toPgtypeText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

// Service defines business logic contract for organization onboarding and verification.
type Service interface {
	ApplyOrganization(ctx context.Context, req ApplyOrganizationRequest, applicantUser db.User, clientIP net.IP, userAgent string) (*ApplicantSubmissionResponse, error)
	ListMyOrganizations(ctx context.Context, userID pgtype.UUID) ([]MyOrganizationResponse, error)
	GetTenantOrganization(ctx context.Context, orgID pgtype.UUID) (*OrganizationResponse, error)
	UpdateOrganizationProfile(ctx context.Context, orgID pgtype.UUID, req UpdateOrganizationProfileRequest, actorUserID pgtype.UUID, clientIP net.IP, userAgent string) (*OrganizationResponse, error)
	ListOrganizationMembers(ctx context.Context, orgID pgtype.UUID, roleFilter string, page, limit int) ([]MemberResponse, *PaginationResponse, error)

	ListOrganizationsAdmin(ctx context.Context, statusFilter, typeFilter string, page, limit int) ([]OrganizationResponse, *PaginationResponse, error)
	GetOrganizationAdminDossier(ctx context.Context, orgID pgtype.UUID) (*AdminDossierResponse, error)
	ApproveOrganization(ctx context.Context, orgID pgtype.UUID, req ApproveOrganizationRequest, reviewerUser db.User, clientIP net.IP, userAgent string) (*OrganizationResponse, *MembershipSummaryResponse, error)
	RejectOrganization(ctx context.Context, orgID pgtype.UUID, req RejectOrganizationRequest, reviewerUser db.User, clientIP net.IP, userAgent string) (*OrganizationResponse, error)

	ListPublicVerifiedOrganizations(ctx context.Context, typeFilter string, page, limit int) ([]PublicVerifiedOrganizationResponse, *PaginationResponse, error)
	GetPublicVerifiedOrganization(ctx context.Context, orgID pgtype.UUID) (*PublicVerifiedOrganizationResponse, error)
}

type serviceImpl struct {
	repo Repository
}

// NewService constructs a new organizations Service.
func NewService(repo Repository) Service {
	return &serviceImpl{repo: repo}
}

func (s *serviceImpl) ApplyOrganization(
	ctx context.Context,
	req ApplyOrganizationRequest,
	applicantUser db.User,
	clientIP net.IP,
	userAgent string,
) (*ApplicantSubmissionResponse, error) {
	if err := req.ValidateAndCanonicalize(); err != nil {
		return nil, err
	}

	var applicantRole string
	switch req.OrgType {
	case "UNIVERSITY":
		applicantRole = "UNIVERSITY_ADMIN"
	case "COMPANY":
		applicantRole = "COMPANY_ADMIN"
	default:
		return nil, core.NewAppError(core.ErrCodeBadRequest, "Invalid organization type")
	}

	var tradeNameText pgtype.Text
	if req.TradeName != nil && *req.TradeName != "" {
		tradeNameText = pgtype.Text{String: *req.TradeName, Valid: true}
	}

	orgParams := db.CreateOrganizationParams{
		OrgType:            req.OrgType,
		LegalName:          req.LegalName,
		TradeName:          tradeNameText,
		CountryCode:        req.CountryCode,
		RegistrationNumber: req.RegistrationNumber,
		OfficialDomain:     req.OfficialDomain,
	}

	// Minimal audit payload: no registration number, domain, legal name, or PII
	auditPayload, _ := json.Marshal(map[string]interface{}{
		"org_type": req.OrgType,
	})

	auditParams := db.CreateAuditLogParams{
		ActorUserID:  applicantUser.ID,
		Action:       "ORGANIZATION_APPLICATION_SUBMITTED",
		ResourceType: "ORGANIZATION",
		Payload:      auditPayload,
		IpAddress:    toNetipAddr(clientIP),
		UserAgent:    toPgtypeText(userAgent),
	}

	org, membership, err := s.repo.ApplyOrganizationTx(ctx, orgParams, applicantUser.ID, applicantRole, auditParams)
	if err != nil {
		return nil, err
	}

	return &ApplicantSubmissionResponse{
		Organization: mapOrganizationToResponse(org, false),
		Membership: MembershipSummaryResponse{
			ID:       uuidToString(membership.ID),
			Role:     membership.Role,
			IsActive: membership.IsActive,
		},
	}, nil
}

func (s *serviceImpl) ListMyOrganizations(ctx context.Context, userID pgtype.UUID) ([]MyOrganizationResponse, error) {
	rows, err := s.repo.ListOrganizationsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	result := make([]MyOrganizationResponse, 0, len(rows))
	for _, r := range rows {
		item := MyOrganizationResponse{
			ID:                 uuidToString(r.ID),
			OrgType:            r.OrgType,
			LegalName:          r.LegalName,
			CountryCode:        r.CountryCode,
			RegistrationNumber: r.RegistrationNumber,
			OfficialDomain:     r.OfficialDomain,
			VerificationStatus: r.VerificationStatus,
			MyRole:             r.UserRole,
			MyIsActive:         r.UserIsActive,
			CreatedAt:          formatTimestamptz(r.CreatedAt),
			UpdatedAt:          formatTimestamptz(r.UpdatedAt),
		}
		if r.TradeName.Valid && r.TradeName.String != "" {
			item.TradeName = &r.TradeName.String
		}
		if r.VerificationStatus == "REJECTED" && r.DecisionReason.Valid && r.DecisionReason.String != "" {
			item.DecisionReason = &r.DecisionReason.String
		}
		result = append(result, item)
	}

	return result, nil
}

func (s *serviceImpl) GetTenantOrganization(ctx context.Context, orgID pgtype.UUID) (*OrganizationResponse, error) {
	org, err := s.repo.GetOrganizationByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, core.NewAppError(core.ErrCodeOrganizationNotFound, "Organization not found")
		}
		return nil, err
	}

	resp := mapOrganizationToResponse(org, false)
	return &resp, nil
}

func (s *serviceImpl) UpdateOrganizationProfile(
	ctx context.Context,
	orgID pgtype.UUID,
	req UpdateOrganizationProfileRequest,
	actorUserID pgtype.UUID,
	clientIP net.IP,
	userAgent string,
) (*OrganizationResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	auditPayload, _ := json.Marshal(map[string]interface{}{
		"updated_fields": []string{"trade_name"},
	})

	auditParams := db.CreateAuditLogParams{
		ActorUserID:  actorUserID,
		Action:       "ORGANIZATION_PROFILE_UPDATED",
		ResourceType: "ORGANIZATION",
		Payload:      auditPayload,
		IpAddress:    toNetipAddr(clientIP),
		UserAgent:    toPgtypeText(userAgent),
	}

	org, err := s.repo.UpdateOrganizationProfile(ctx, orgID, req.TradeName, auditParams)
	if err != nil {
		return nil, err
	}

	resp := mapOrganizationToResponse(org, false)
	return &resp, nil
}

func (s *serviceImpl) ListOrganizationMembers(
	ctx context.Context,
	orgID pgtype.UUID,
	roleFilter string,
	page, limit int,
) ([]MemberResponse, *PaginationResponse, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	} else if limit > 50 {
		limit = 50
	}

	var roleText pgtype.Text
	if roleFilter != "" {
		if !allowedMemberRoles[roleFilter] {
			return nil, nil, core.NewAppError(core.ErrCodeInvalidFilterParam, "Invalid role filter")
		}
		roleText = pgtype.Text{String: roleFilter, Valid: true}
	}

	offset := int32((page - 1) * limit)

	totalRecords, err := s.repo.CountActiveOrganizationMembers(ctx, db.CountActiveOrganizationMembersParams{
		OrganizationID: orgID,
		Role:           roleText,
	})
	if err != nil {
		return nil, nil, err
	}

	rows, err := s.repo.ListActiveOrganizationMembers(ctx, db.ListActiveOrganizationMembersParams{
		OrganizationID: orgID,
		Role:           roleText,
		Limit:          int32(limit),
		Offset:         offset,
	})
	if err != nil {
		return nil, nil, err
	}

	members := make([]MemberResponse, 0, len(rows))
	for _, r := range rows {
		members = append(members, MemberResponse{
			ID:        uuidToString(r.ID),
			UserID:    uuidToString(r.UserID),
			FullName:  r.UserFullName,
			Email:     r.UserEmail,
			Role:      r.Role,
			IsActive:  r.IsActive,
			CreatedAt: formatTimestamptz(r.CreatedAt),
		})
	}

	totalPages := int(math.Ceil(float64(totalRecords) / float64(limit)))
	if totalPages < 1 {
		totalPages = 1
	}

	pagination := &PaginationResponse{
		Page:         page,
		Limit:        limit,
		TotalRecords: totalRecords,
		TotalPages:   totalPages,
	}

	return members, pagination, nil
}

func (s *serviceImpl) ListOrganizationsAdmin(
	ctx context.Context,
	statusFilter, typeFilter string,
	page, limit int,
) ([]OrganizationResponse, *PaginationResponse, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	} else if limit > 100 {
		limit = 100
	}

	var statusText pgtype.Text
	if statusFilter != "" {
		if !allowedVerificationStatuses[statusFilter] {
			return nil, nil, core.NewAppError(core.ErrCodeInvalidFilterParam, "Invalid verification_status filter")
		}
		statusText = pgtype.Text{String: statusFilter, Valid: true}
	}

	var typeText pgtype.Text
	if typeFilter != "" {
		if !allowedOrgTypes[typeFilter] {
			return nil, nil, core.NewAppError(core.ErrCodeInvalidFilterParam, "Invalid org_type filter")
		}
		typeText = pgtype.Text{String: typeFilter, Valid: true}
	}

	offset := int32((page - 1) * limit)

	totalRecords, err := s.repo.CountOrganizationsFiltered(ctx, db.CountOrganizationsFilteredParams{
		VerificationStatus: statusText,
		OrgType:            typeText,
	})
	if err != nil {
		return nil, nil, err
	}

	rows, err := s.repo.ListOrganizationsFiltered(ctx, db.ListOrganizationsFilteredParams{
		VerificationStatus: statusText,
		OrgType:            typeText,
		Limit:              int32(limit),
		Offset:             offset,
	})
	if err != nil {
		return nil, nil, err
	}

	orgs := make([]OrganizationResponse, 0, len(rows))
	for _, r := range rows {
		orgs = append(orgs, mapOrganizationToResponse(r, true))
	}

	totalPages := int(math.Ceil(float64(totalRecords) / float64(limit)))
	if totalPages < 1 {
		totalPages = 1
	}

	pagination := &PaginationResponse{
		Page:         page,
		Limit:        limit,
		TotalRecords: totalRecords,
		TotalPages:   totalPages,
	}

	return orgs, pagination, nil
}

func (s *serviceImpl) GetOrganizationAdminDossier(ctx context.Context, orgID pgtype.UUID) (*AdminDossierResponse, error) {
	org, members, err := s.repo.GetOrganizationApplicationForAdmin(ctx, orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, core.NewAppError(core.ErrCodeOrganizationNotFound, "Organization not found")
		}
		return nil, err
	}

	if org.VerificationStatus == "PENDING" && len(members) != 1 {
		return nil, core.NewAppError(core.ErrCodeOrganizationMembershipIntegrityViolation, "Pending application must have exactly one applicant membership")
	}

	var applicantSummary ApplicantSummaryResponse
	if len(members) > 0 {
		m := members[0]
		applicantSummary = ApplicantSummaryResponse{
			UserID:              uuidToString(m.UserID),
			FullName:            m.UserFullName,
			Email:               m.UserEmail,
			MembershipID:        uuidToString(m.MembershipID),
			Role:                m.Role,
			IsActive:            m.IsActive,
			MembershipCreatedAt: formatTimestamptz(m.MembershipCreatedAt),
		}
	}

	return &AdminDossierResponse{
		Organization: mapOrganizationToResponse(org, true),
		Applicant:    applicantSummary,
	}, nil
}

func (s *serviceImpl) ApproveOrganization(
	ctx context.Context,
	orgID pgtype.UUID,
	req ApproveOrganizationRequest,
	reviewerUser db.User,
	clientIP net.IP,
	userAgent string,
) (*OrganizationResponse, *MembershipSummaryResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, nil, err
	}

	auditPayload, _ := json.Marshal(map[string]interface{}{
		"action":          "ORGANIZATION_APPROVED",
		"previous_status": "PENDING",
		"new_status":      "VERIFIED",
	})

	auditParams := db.CreateAuditLogParams{
		ActorUserID:  reviewerUser.ID,
		Action:       "ORGANIZATION_APPROVED",
		ResourceType: "ORGANIZATION",
		Payload:      auditPayload,
		IpAddress:    toNetipAddr(clientIP),
		UserAgent:    toPgtypeText(userAgent),
	}

	reviewedOrg, activatedMembership, err := s.repo.ApproveOrganizationTx(
		ctx,
		orgID,
		reviewerUser.ID,
		req.Reason,
		auditParams,
	)
	if err != nil {
		return nil, nil, err
	}

	orgResp := mapOrganizationToResponse(reviewedOrg, true)
	membershipSummary := &MembershipSummaryResponse{
		ID:       uuidToString(activatedMembership.ID),
		Role:     activatedMembership.Role,
		IsActive: activatedMembership.IsActive,
	}

	return &orgResp, membershipSummary, nil
}

func (s *serviceImpl) RejectOrganization(
	ctx context.Context,
	orgID pgtype.UUID,
	req RejectOrganizationRequest,
	reviewerUser db.User,
	clientIP net.IP,
	userAgent string,
) (*OrganizationResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	// Store reason_code in audit JSON; NEVER copy free-text decision_reason into audit payload
	auditPayload, _ := json.Marshal(map[string]interface{}{
		"action":          "ORGANIZATION_REJECTED",
		"previous_status": "PENDING",
		"new_status":      "REJECTED",
		"reason_code":     req.ReasonCode,
	})

	auditParams := db.CreateAuditLogParams{
		ActorUserID:  reviewerUser.ID,
		Action:       "ORGANIZATION_REJECTED",
		ResourceType: "ORGANIZATION",
		Payload:      auditPayload,
		IpAddress:    toNetipAddr(clientIP),
		UserAgent:    toPgtypeText(userAgent),
	}

	rejectedOrg, err := s.repo.RejectOrganizationTx(
		ctx,
		orgID,
		reviewerUser.ID,
		req.DecisionReason,
		req.ReasonCode,
		auditParams,
	)
	if err != nil {
		return nil, err
	}

	resp := mapOrganizationToResponse(rejectedOrg, true)
	return &resp, nil
}

func (s *serviceImpl) ListPublicVerifiedOrganizations(
	ctx context.Context,
	typeFilter string,
	page, limit int,
) ([]PublicVerifiedOrganizationResponse, *PaginationResponse, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	} else if limit > 50 {
		limit = 50
	}

	var typeText pgtype.Text
	if typeFilter != "" {
		if !allowedOrgTypes[typeFilter] {
			return nil, nil, core.NewAppError(core.ErrCodeInvalidFilterParam, "Invalid org_type filter")
		}
		typeText = pgtype.Text{String: typeFilter, Valid: true}
	}

	offset := int32((page - 1) * limit)

	totalRecords, err := s.repo.CountPublicVerifiedOrganizations(ctx, typeText)
	if err != nil {
		return nil, nil, err
	}

	rows, err := s.repo.ListPublicVerifiedOrganizations(ctx, db.ListPublicVerifiedOrganizationsParams{
		OrgType: typeText,
		Limit:   int32(limit),
		Offset:  offset,
	})
	if err != nil {
		return nil, nil, err
	}

	result := make([]PublicVerifiedOrganizationResponse, 0, len(rows))
	for _, r := range rows {
		item := PublicVerifiedOrganizationResponse{
			ID:             uuidToString(r.ID),
			OrgType:        r.OrgType,
			LegalName:      r.LegalName,
			CountryCode:    r.CountryCode,
			OfficialDomain: r.OfficialDomain,
			CreatedAt:      formatTimestamptz(r.CreatedAt),
		}
		if r.TradeName.Valid && r.TradeName.String != "" {
			item.TradeName = &r.TradeName.String
		}
		result = append(result, item)
	}

	totalPages := int(math.Ceil(float64(totalRecords) / float64(limit)))
	if totalPages < 1 {
		totalPages = 1
	}

	pagination := &PaginationResponse{
		Page:         page,
		Limit:        limit,
		TotalRecords: totalRecords,
		TotalPages:   totalPages,
	}

	return result, pagination, nil
}

func (s *serviceImpl) GetPublicVerifiedOrganization(ctx context.Context, orgID pgtype.UUID) (*PublicVerifiedOrganizationResponse, error) {
	r, err := s.repo.GetPublicVerifiedOrganizationByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, core.NewAppError(core.ErrCodeOrganizationNotFound, "Organization not found or not publicly available")
		}
		return nil, err
	}

	item := &PublicVerifiedOrganizationResponse{
		ID:             uuidToString(r.ID),
		OrgType:        r.OrgType,
		LegalName:      r.LegalName,
		CountryCode:    r.CountryCode,
		OfficialDomain: r.OfficialDomain,
		CreatedAt:      formatTimestamptz(r.CreatedAt),
	}
	if r.TradeName.Valid && r.TradeName.String != "" {
		item.TradeName = &r.TradeName.String
	}

	return item, nil
}
