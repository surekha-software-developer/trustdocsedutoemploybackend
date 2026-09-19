package organizations

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
)

// OrganizationResponse represents safe tenant/admin projection of an organization.
type OrganizationResponse struct {
	ID                 string  `json:"id"`
	OrgType            string  `json:"org_type"`
	LegalName          string  `json:"legal_name"`
	TradeName          *string `json:"trade_name,omitempty"`
	CountryCode        string  `json:"country_code"`
	RegistrationNumber string  `json:"registration_number,omitempty"`
	OfficialDomain     string  `json:"official_domain"`
	VerificationStatus string  `json:"verification_status"`
	ReviewedByUserID   *string `json:"reviewed_by_user_id,omitempty"`
	ReviewedAt         *string `json:"reviewed_at,omitempty"`
	DecisionReason     *string `json:"decision_reason,omitempty"`
	CreatedAt          string  `json:"created_at"`
	UpdatedAt          string  `json:"updated_at"`
}

// MembershipSummaryResponse represents applicant's initial membership info.
type MembershipSummaryResponse struct {
	ID       string `json:"id"`
	Role     string `json:"role"`
	IsActive bool   `json:"is_active"`
}

// ApplicantSubmissionResponse is returned upon successful application submission.
type ApplicantSubmissionResponse struct {
	Organization OrganizationResponse      `json:"organization"`
	Membership   MembershipSummaryResponse `json:"membership"`
}

// MyOrganizationResponse is returned by /organizations/mine.
type MyOrganizationResponse struct {
	ID                 string  `json:"id"`
	OrgType            string  `json:"org_type"`
	LegalName          string  `json:"legal_name"`
	TradeName          *string `json:"trade_name,omitempty"`
	CountryCode        string  `json:"country_code"`
	RegistrationNumber string  `json:"registration_number"`
	OfficialDomain     string  `json:"official_domain"`
	VerificationStatus string  `json:"verification_status"`
	DecisionReason     *string `json:"decision_reason,omitempty"`
	MyRole             string  `json:"my_role"`
	MyIsActive         bool    `json:"my_is_active"`
	CreatedAt          string  `json:"created_at"`
	UpdatedAt          string  `json:"updated_at"`
}

// ApplicantSummaryResponse represents the applicant's identity in the administrative dossier.
type ApplicantSummaryResponse struct {
	UserID              string `json:"user_id"`
	FullName            string `json:"full_name"`
	Email               string `json:"email"`
	MembershipID        string `json:"membership_id"`
	Role                string `json:"role"`
	IsActive            bool   `json:"is_active"`
	MembershipCreatedAt string `json:"membership_created_at"`
}

// AdminDossierResponse represents complete administrative dossier for Superadmin review.
type AdminDossierResponse struct {
	Organization OrganizationResponse     `json:"organization"`
	Applicant    ApplicantSummaryResponse `json:"applicant"`
}

// PublicVerifiedOrganizationResponse represents safe public directory projection.
type PublicVerifiedOrganizationResponse struct {
	ID             string  `json:"id"`
	OrgType        string  `json:"org_type"`
	LegalName      string  `json:"legal_name"`
	TradeName      *string `json:"trade_name,omitempty"`
	CountryCode    string  `json:"country_code"`
	OfficialDomain string  `json:"official_domain"`
	CreatedAt      string  `json:"created_at"`
}

// MemberResponse represents active member record returned to verified organization admins.
type MemberResponse struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	FullName  string `json:"full_name"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	IsActive  bool   `json:"is_active"`
	CreatedAt string `json:"created_at"`
}

// PaginationResponse represents pagination metadata envelope.
type PaginationResponse struct {
	Page         int   `json:"page"`
	Limit        int   `json:"limit"`
	TotalRecords int64 `json:"total_records"`
	TotalPages   int   `json:"total_pages"`
}

// Helper converters from sqlc types to response DTOs

func uuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	src := u.Bytes
	return timeUUIDFormat(src)
}

func timeUUIDFormat(b [16]byte) string {
	return formatUUID(b)
}

func formatUUID(b [16]byte) string {
	return string([]byte{
		hexChars[b[0]>>4], hexChars[b[0]&0xf],
		hexChars[b[1]>>4], hexChars[b[1]&0xf],
		hexChars[b[2]>>4], hexChars[b[2]&0xf],
		hexChars[b[3]>>4], hexChars[b[3]&0xf],
		'-',
		hexChars[b[4]>>4], hexChars[b[4]&0xf],
		hexChars[b[5]>>4], hexChars[b[5]&0xf],
		'-',
		hexChars[b[6]>>4], hexChars[b[6]&0xf],
		hexChars[b[7]>>4], hexChars[b[7]&0xf],
		'-',
		hexChars[b[8]>>4], hexChars[b[8]&0xf],
		hexChars[b[9]>>4], hexChars[b[9]&0xf],
		'-',
		hexChars[b[10]>>4], hexChars[b[10]&0xf],
		hexChars[b[11]>>4], hexChars[b[11]&0xf],
		hexChars[b[12]>>4], hexChars[b[12]&0xf],
		hexChars[b[13]>>4], hexChars[b[13]&0xf],
		hexChars[b[14]>>4], hexChars[b[14]&0xf],
		hexChars[b[15]>>4], hexChars[b[15]&0xf],
	})
}

const hexChars = "0123456789abcdef"

func formatTimestamptz(t pgtype.Timestamptz) string {
	if !t.Valid {
		return ""
	}
	return t.Time.UTC().Format(time.RFC3339)
}

func mapOrganizationToResponse(o db.Organization, includeAdminFields bool) OrganizationResponse {
	resp := OrganizationResponse{
		ID:                 uuidToString(o.ID),
		OrgType:            o.OrgType,
		LegalName:          o.LegalName,
		CountryCode:        o.CountryCode,
		RegistrationNumber: o.RegistrationNumber,
		OfficialDomain:     o.OfficialDomain,
		VerificationStatus: o.VerificationStatus,
		CreatedAt:          formatTimestamptz(o.CreatedAt),
		UpdatedAt:          formatTimestamptz(o.UpdatedAt),
	}
	if o.TradeName.Valid && o.TradeName.String != "" {
		resp.TradeName = &o.TradeName.String
	}
	if includeAdminFields {
		if o.ReviewedByUserID.Valid {
			s := uuidToString(o.ReviewedByUserID)
			resp.ReviewedByUserID = &s
		}
		if o.ReviewedAt.Valid {
			s := formatTimestamptz(o.ReviewedAt)
			resp.ReviewedAt = &s
		}
		if o.DecisionReason.Valid && o.DecisionReason.String != "" {
			resp.DecisionReason = &o.DecisionReason.String
		}
	}
	return resp
}
