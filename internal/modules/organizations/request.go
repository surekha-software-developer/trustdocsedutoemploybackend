package organizations

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
)

var (
	countryCodeRegex = regexp.MustCompile(`^[A-Z]{2}$`)
	domainRegex      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// Allowlisted Reason Codes for application rejection
const (
	ReasonCodeRegistrationNotVerified = "REGISTRATION_NOT_VERIFIED"
	ReasonCodeDomainNotVerified       = "DOMAIN_NOT_VERIFIED"
	ReasonCodeIneligibleOrganization  = "INELIGIBLE_ORGANIZATION"
	ReasonCodeDuplicateApplication    = "DUPLICATE_APPLICATION"
	ReasonCodeInsufficientInformation = "INSUFFICIENT_INFORMATION"
	ReasonCodeOther                   = "OTHER"
)

var allowedReasonCodes = map[string]bool{
	ReasonCodeRegistrationNotVerified: true,
	ReasonCodeDomainNotVerified:       true,
	ReasonCodeIneligibleOrganization:  true,
	ReasonCodeDuplicateApplication:    true,
	ReasonCodeInsufficientInformation: true,
	ReasonCodeOther:                   true,
}

var allowedOrgTypes = map[string]bool{
	"UNIVERSITY": true,
	"COMPANY":    true,
}

var allowedVerificationStatuses = map[string]bool{
	"PENDING":   true,
	"VERIFIED":  true,
	"REJECTED":  true,
	"SUSPENDED": true,
}

var allowedMemberRoles = map[string]bool{
	"UNIVERSITY_ADMIN":  true,
	"UNIVERSITY_ISSUER": true,
	"COMPANY_ADMIN":     true,
	"COMPANY_VERIFIER":  true,
}

// ApplyOrganizationRequest represents payload to submit a new organization onboarding application.
type ApplyOrganizationRequest struct {
	OrgType            string  `json:"org_type"`
	LegalName          string  `json:"legal_name"`
	TradeName          *string `json:"trade_name"`
	CountryCode        string  `json:"country_code"`
	RegistrationNumber string  `json:"registration_number"`
	OfficialDomain     string  `json:"official_domain"`
}

// ValidateAndCanonicalize sanitizes and validates input data strictly according to schema check constraints.
func (r *ApplyOrganizationRequest) ValidateAndCanonicalize() *core.AppError {
	r.OrgType = strings.TrimSpace(r.OrgType)
	if !allowedOrgTypes[r.OrgType] {
		return core.NewAppError(core.ErrCodeBadRequest, "Invalid org_type. Must be 'UNIVERSITY' or 'COMPANY'")
	}

	r.LegalName = strings.TrimSpace(r.LegalName)
	if l := utf8.RuneCountInString(r.LegalName); l < 2 || l > 255 {
		return core.NewAppError(core.ErrCodeBadRequest, "legal_name must be between 2 and 255 characters")
	}

	if r.TradeName != nil {
		tn := strings.TrimSpace(*r.TradeName)
		if tn == "" {
			r.TradeName = nil
		} else {
			if l := utf8.RuneCountInString(tn); l > 255 {
				return core.NewAppError(core.ErrCodeBadRequest, "trade_name cannot exceed 255 characters")
			}
			r.TradeName = &tn
		}
	}

	r.CountryCode = strings.ToUpper(strings.TrimSpace(r.CountryCode))
	if !countryCodeRegex.MatchString(r.CountryCode) {
		return core.NewAppError(core.ErrCodeBadRequest, "country_code must be an ISO 3166-1 alpha-2 two-letter uppercase code")
	}

	r.RegistrationNumber = strings.ToUpper(strings.TrimSpace(r.RegistrationNumber))
	if l := utf8.RuneCountInString(r.RegistrationNumber); l < 1 || l > 100 {
		return core.NewAppError(core.ErrCodeBadRequest, "registration_number must be between 1 and 100 characters")
	}

	r.OfficialDomain = strings.ToLower(strings.TrimSpace(r.OfficialDomain))
	if strings.ContainsAny(r.OfficialDomain, ":/\\?#") || !domainRegex.MatchString(r.OfficialDomain) || utf8.RuneCountInString(r.OfficialDomain) > 255 {
		return core.NewAppError(core.ErrCodeBadRequest, "official_domain must be a valid lowercase domain name without protocol, port, path, or special characters")
	}

	return nil
}

// ApproveOrganizationRequest represents optional payload for Superadmin approval.
type ApproveOrganizationRequest struct {
	Reason *string `json:"reason"`
}

// Validate sanitizes and validates approval review notes.
func (r *ApproveOrganizationRequest) Validate() *core.AppError {
	if r.Reason != nil {
		rs := strings.TrimSpace(*r.Reason)
		if rs == "" {
			r.Reason = nil
		} else {
			if utf8.RuneCountInString(rs) > 500 {
				return core.NewAppError(core.ErrCodeBadRequest, "reason cannot exceed 500 characters")
			}
			r.Reason = &rs
		}
	}
	return nil
}

// RejectOrganizationRequest represents mandatory rejection payload with classification.
type RejectOrganizationRequest struct {
	DecisionReason string `json:"decision_reason"`
	ReasonCode     string `json:"reason_code"`
}

// Validate enforces mandatory non-empty reason and allowlisted reason_code.
func (r *RejectOrganizationRequest) Validate() *core.AppError {
	r.DecisionReason = strings.TrimSpace(r.DecisionReason)
	if l := utf8.RuneCountInString(r.DecisionReason); l < 5 || l > 1000 {
		return core.NewAppError(core.ErrCodeDecisionReasonRequired, "decision_reason is required and must be between 5 and 1000 characters")
	}

	r.ReasonCode = strings.TrimSpace(r.ReasonCode)
	if !allowedReasonCodes[r.ReasonCode] {
		return core.NewAppError(core.ErrCodeInvalidReasonCode, fmt.Sprintf("Invalid reason_code. Must be one of: %s, %s, %s, %s, %s, %s",
			ReasonCodeRegistrationNotVerified, ReasonCodeDomainNotVerified, ReasonCodeIneligibleOrganization,
			ReasonCodeDuplicateApplication, ReasonCodeInsufficientInformation, ReasonCodeOther))
	}

	return nil
}

// UpdateOrganizationProfileRequest represents request by active admin to update mutable fields.
type UpdateOrganizationProfileRequest struct {
	TradeName *string `json:"trade_name"`
}

// Validate ensures trade_name meets length bounds.
func (r *UpdateOrganizationProfileRequest) Validate() *core.AppError {
	if r.TradeName != nil {
		tn := strings.TrimSpace(*r.TradeName)
		if tn == "" {
			r.TradeName = nil
		} else {
			if utf8.RuneCountInString(tn) > 255 {
				return core.NewAppError(core.ErrCodeBadRequest, "trade_name cannot exceed 255 characters")
			}
			r.TradeName = &tn
		}
	}
	return nil
}

// ValidateEmailHelper is a helper for email validations where needed.
func ValidateEmailHelper(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
