package organizations

import (
	"github.com/gin-gonic/gin"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/middleware"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
)

// RegisterRoutes sets up all 11 organization endpoints under /api/v1 with their exact middleware chains.
func RegisterRoutes(
	rg *gin.RouterGroup,
	h *Handler,
	authRepo auth.Repository,
	orgRepo Repository,
	originMw gin.HandlerFunc,
	jsonMw gin.HandlerFunc,
	authMw gin.HandlerFunc,
	csrfMw gin.HandlerFunc,
	publicRateLimitMw gin.HandlerFunc,
) {
	// Middleware declarations
	nonSuperadminMw := middleware.RequireNonSuperadmin()
	superadminMw := middleware.RequireSuperadmin()
	orgMembershipMw := middleware.RequireOrgMembership(authRepo, "organization_id")
	verifiedOrgMw := middleware.RequireVerifiedOrganization(orgRepo, "organization_id")
	orgAdminRoleMw := middleware.RequireOrgRole(authRepo, "UNIVERSITY_ADMIN", "COMPANY_ADMIN")

	// ==========================================
	// 1. Applicant Endpoints
	// ==========================================
	rg.POST("/organizations", originMw, jsonMw, authMw, csrfMw, nonSuperadminMw, h.ApplyOrganization)
	rg.GET("/organizations/mine", authMw, h.ListMyOrganizations)

	// ==========================================
	// 2. Verified Tenant Member Endpoints
	// ==========================================
	rg.GET("/organizations/:organization_id", authMw, orgMembershipMw, verifiedOrgMw, h.GetTenantOrganization)
	rg.PATCH("/organizations/:organization_id", originMw, jsonMw, authMw, csrfMw, orgMembershipMw, verifiedOrgMw, orgAdminRoleMw, h.UpdateOrganizationProfile)
	rg.GET("/organizations/:organization_id/members", authMw, orgMembershipMw, verifiedOrgMw, orgAdminRoleMw, h.ListOrganizationMembers)

	// ==========================================
	// 3. TrustDocs Superadmin Review Endpoints
	// ==========================================
	rg.GET("/admin/organizations", authMw, superadminMw, h.ListOrganizationsAdmin)
	rg.GET("/admin/organizations/:organization_id", authMw, superadminMw, h.GetOrganizationAdminDossier)
	rg.POST("/admin/organizations/:organization_id/approve", originMw, jsonMw, authMw, csrfMw, superadminMw, h.ApproveOrganization)
	rg.POST("/admin/organizations/:organization_id/reject", originMw, jsonMw, authMw, csrfMw, superadminMw, h.RejectOrganization)

	// ==========================================
	// 4. Public Directory Endpoints
	// ==========================================
	rg.GET("/public/verified-organizations", publicRateLimitMw, h.ListPublicVerifiedOrganizations)
	rg.GET("/public/organizations/:organization_id", publicRateLimitMw, h.GetPublicVerifiedOrganization)
}
