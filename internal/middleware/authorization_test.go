package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/auth"
)

type mockRepoForAuthz struct {
	auth.Repository
	membership db.OrganizationMembership
	failMember bool
}

func (m *mockRepoForAuthz) GetMembership(ctx context.Context, orgID, userID pgtype.UUID) (db.OrganizationMembership, error) {
	if m.failMember {
		return db.OrganizationMembership{}, errors.New("not found")
	}
	return m.membership, nil
}

func TestRequireSuperadminAndNonSuperadmin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var currentUser db.User
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user", currentUser)
		c.Next()
	})
	r.GET("/superadmin-only", RequireSuperadmin(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	r.GET("/non-superadmin-only", RequireNonSuperadmin(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// 1. Regular user trying superadmin endpoint -> 403
	currentUser = db.User{IsSuperadmin: false}
	req1, _ := http.NewRequest(http.MethodGet, "/superadmin-only", nil)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-superadmin, got %d", w1.Code)
	}

	// 2. Superadmin accessing superadmin endpoint -> 200
	currentUser = db.User{IsSuperadmin: true}
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req1)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 for superadmin, got %d", w2.Code)
	}

	// 3. Superadmin trying non-superadmin endpoint -> 403
	currentUser = db.User{IsSuperadmin: true}
	req3, _ := http.NewRequest(http.MethodGet, "/non-superadmin-only", nil)
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusForbidden {
		t.Errorf("expected 403 for superadmin on non-superadmin endpoint, got %d", w3.Code)
	}

	// 4. Regular user accessing non-superadmin endpoint -> 200
	currentUser = db.User{IsSuperadmin: false}
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req3)
	if w4.Code != http.StatusOK {
		t.Errorf("expected 200 for regular user on non-superadmin endpoint, got %d", w4.Code)
	}
}

func TestRequireOrgMembershipAndRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var orgUUID, userUUID pgtype.UUID
	_ = orgUUID.Scan("22222222-2222-2222-2222-222222222222")
	_ = userUUID.Scan("00000000-0000-0000-0000-000000000001")

	mockRepo := &mockRepoForAuthz{
		membership: db.OrganizationMembership{
			OrganizationID: orgUUID,
			UserID:         userUUID,
			Role:           "ADMIN",
			IsActive:       true,
		},
	}

	var currentUser db.User
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user", currentUser)
		c.Next()
	})
	r.GET("/orgs/:org_id/admin", RequireOrgMembership(mockRepo), RequireOrgRole(mockRepo, "ADMIN"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	currentUser = db.User{ID: userUUID}

	// 1. Valid member with ADMIN role -> 200
	req1, _ := http.NewRequest(http.MethodGet, "/orgs/22222222-2222-2222-2222-222222222222/admin", nil)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("expected 200 for admin member, got %d", w1.Code)
	}

	// 2. Member with insufficient role (e.g. VIEWER) -> 403
	mockRepo.membership.Role = "VIEWER"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req1)
	if w2.Code != http.StatusForbidden {
		t.Errorf("expected 403 for viewer role, got %d", w2.Code)
	}

	// 3. Inactive membership -> 403
	mockRepo.membership.Role = "ADMIN"
	mockRepo.membership.IsActive = false
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req1)
	if w3.Code != http.StatusForbidden {
		t.Errorf("expected 403 for inactive membership, got %d", w3.Code)
	}

	// 4. Non-member (error looking up membership) -> 403
	mockRepo.failMember = true
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req1)
	if w4.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-member, got %d", w4.Code)
	}
}
