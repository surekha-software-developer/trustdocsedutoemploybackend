package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
)

// RequireSuperadmin enforces that the authenticated user possesses superadmin status.
func RequireSuperadmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		userVal, exists := c.Get("user")
		if !exists {
			core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
			c.Abort()
			return
		}

		user, ok := userVal.(db.User)
		if !ok || !user.IsSuperadmin {
			core.SendError(c, http.StatusForbidden, core.ErrCodeForbidden, "Superadmin privileges required")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireNonSuperadmin enforces that the authenticated user is NOT a superadmin (portal isolation).
func RequireNonSuperadmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		userVal, exists := c.Get("user")
		if !exists {
			core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
			c.Abort()
			return
		}

		user, ok := userVal.(db.User)
		if !ok || user.IsSuperadmin {
			core.SendError(c, http.StatusForbidden, core.ErrCodeForbidden, "Operation prohibited for superadmin accounts")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireOrgMembership verifies that the user is an active member of the specified organization.
func RequireOrgMembership(repo auth.Repository, paramName ...string) gin.HandlerFunc {
	param := "org_id"
	if len(paramName) > 0 && paramName[0] != "" {
		param = paramName[0]
	}

	return func(c *gin.Context) {
		userVal, exists := c.Get("user")
		if !exists {
			core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
			c.Abort()
			return
		}

		user, ok := userVal.(db.User)
		if !ok {
			core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "Invalid user context")
			c.Abort()
			return
		}

		orgIDStr := c.Param(param)
		var orgUUID pgtype.UUID
		if err := orgUUID.Scan(orgIDStr); err != nil {
			core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid organization ID parameter")
			c.Abort()
			return
		}

		membership, err := repo.GetMembership(c.Request.Context(), orgUUID, user.ID)
		if err != nil || !membership.IsActive {
			core.SendError(c, http.StatusForbidden, core.ErrCodeForbidden, "Active organization membership required")
			c.Abort()
			return
		}

		c.Set("membership", membership)
		c.Next()
	}
}

// RequireOrgRole verifies that the user belongs to the organization and holds one of the required roles.
func RequireOrgRole(repo auth.Repository, allowedRoles ...string) gin.HandlerFunc {
	roleMap := make(map[string]bool)
	for _, r := range allowedRoles {
		roleMap[r] = true
	}

	return func(c *gin.Context) {
		userVal, exists := c.Get("user")
		if !exists {
			core.SendError(c, http.StatusUnauthorized, core.ErrCodeUnauthorized, "Authentication required")
			c.Abort()
			return
		}

		user, ok := userVal.(db.User)
		if !ok {
			core.SendError(c, http.StatusInternalServerError, core.ErrCodeInternal, "Invalid user context")
			c.Abort()
			return
		}

		// Try to read existing membership from context, or query from repository
		var membership db.OrganizationMembership
		mVal, mExists := c.Get("membership")
		if mExists {
			membership = mVal.(db.OrganizationMembership)
		} else {
			orgIDStr := c.Param("org_id")
			var orgUUID pgtype.UUID
			if err := orgUUID.Scan(orgIDStr); err != nil {
				core.SendError(c, http.StatusBadRequest, core.ErrCodeBadRequest, "Invalid organization ID parameter")
				c.Abort()
				return
			}
			var err error
			membership, err = repo.GetMembership(c.Request.Context(), orgUUID, user.ID)
			if err != nil || !membership.IsActive {
				core.SendError(c, http.StatusForbidden, core.ErrCodeForbidden, "Active organization membership required")
				c.Abort()
				return
			}
			c.Set("membership", membership)
		}

		if !roleMap[membership.Role] {
			core.SendError(c, http.StatusForbidden, core.ErrCodeForbidden, "Insufficient organization role permissions")
			c.Abort()
			return
		}

		c.Next()
	}
}
