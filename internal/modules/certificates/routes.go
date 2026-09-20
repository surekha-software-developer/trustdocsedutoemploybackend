package certificates

import (
	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/middleware"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/organizations"
)

// RegisterRoutes registers all Phase 5A certificate routes with their exact middleware chains.
func RegisterRoutes(
	rg *gin.RouterGroup,
	h *Handler,
	authRepo auth.Repository,
	orgRepo organizations.Repository,
	originMw gin.HandlerFunc,
	jsonMw gin.HandlerFunc,
	authMw gin.HandlerFunc,
	csrfMw gin.HandlerFunc,
	publicRateLimitMw gin.HandlerFunc,
) {
	nonSuperadminMw := middleware.RequireNonSuperadmin()
	orgMembershipMw := middleware.RequireOrgMembership(authRepo, "organization_id")
	verifiedOrgMw := middleware.RequireVerifiedOrganization(orgRepo, "organization_id")
	universityRoleMw := middleware.RequireOrgRole(authRepo, "UNIVERSITY_ADMIN", "UNIVERSITY_ISSUER")

	// =========================================================================
	// 1. University Issuer Certificate Management Endpoints
	// =========================================================================
	rg.POST("/organizations/:organization_id/certificates", originMw, jsonMw, authMw, csrfMw, nonSuperadminMw, orgMembershipMw, verifiedOrgMw, universityRoleMw, h.CreateDraft)
	rg.PATCH("/organizations/:organization_id/certificates/:certificate_id", originMw, jsonMw, authMw, csrfMw, nonSuperadminMw, orgMembershipMw, verifiedOrgMw, universityRoleMw, h.UpdateDraft)

	// Multipart upload explicitly omits jsonMw
	rg.POST("/organizations/:organization_id/certificates/:certificate_id/file", originMw, authMw, csrfMw, nonSuperadminMw, orgMembershipMw, verifiedOrgMw, universityRoleMw, h.UploadCertificateFile)

	rg.POST("/organizations/:organization_id/certificates/:certificate_id/issue", originMw, authMw, csrfMw, nonSuperadminMw, orgMembershipMw, verifiedOrgMw, universityRoleMw, h.IssueCertificate)
	rg.GET("/organizations/:organization_id/certificates", authMw, nonSuperadminMw, orgMembershipMw, verifiedOrgMw, universityRoleMw, h.ListCertificates)
	rg.GET("/organizations/:organization_id/certificates/:certificate_id", authMw, nonSuperadminMw, orgMembershipMw, verifiedOrgMw, universityRoleMw, h.GetCertificate)
	rg.DELETE("/organizations/:organization_id/certificates/:certificate_id", originMw, authMw, csrfMw, nonSuperadminMw, orgMembershipMw, verifiedOrgMw, universityRoleMw, h.DeleteDraft)

	rg.POST("/organizations/:organization_id/certificates/:certificate_id/revoke", originMw, jsonMw, authMw, csrfMw, nonSuperadminMw, orgMembershipMw, verifiedOrgMw, universityRoleMw, h.RevokeCertificate)
	rg.POST("/organizations/:organization_id/certificates/:certificate_id/replace", originMw, jsonMw, authMw, csrfMw, nonSuperadminMw, orgMembershipMw, verifiedOrgMw, universityRoleMw, h.ReplaceCertificate)

	// =========================================================================
	// 2. Student Career Trust Passport Endpoints
	// =========================================================================
	rg.GET("/certificates/mine", authMw, nonSuperadminMw, h.ListMyCertificates)
	rg.GET("/certificates/mine/:certificate_id", authMw, nonSuperadminMw, h.GetMyCertificate)
	rg.GET("/certificates/:certificate_id/download", authMw, nonSuperadminMw, h.DownloadCertificate)

	// =========================================================================
	// 3. Public Verification Endpoint
	// =========================================================================
	rg.GET("/public/certificates/:public_id", publicRateLimitMw, h.VerifyPublicCertificate)
}
