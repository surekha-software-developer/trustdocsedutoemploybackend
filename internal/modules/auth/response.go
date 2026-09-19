package auth

// MessageResponse provides a standard informational payload.
type MessageResponse struct {
	Message string `json:"message"`
}

// UserResponse provides sanitized user details for clients.
type UserResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	FullName      string `json:"full_name"`
	IsSuperadmin  bool   `json:"is_superadmin"`
	EmailVerified bool   `json:"email_verified"`
}

// MembershipResponse provides active organization membership details.
type MembershipResponse struct {
	OrganizationID        string `json:"organization_id"`
	Role                  string `json:"role"`
	OrganizationLegalName string `json:"organization_legal_name"`
	OrganizationType      string `json:"organization_type"`
	OrganizationStatus    string `json:"organization_status"`
}

// AuthMeResponse bundles user identity and their active organization memberships.
type AuthMeResponse struct {
	User        UserResponse         `json:"user"`
	Memberships []MembershipResponse `json:"memberships"`
}

// CSRFResponse delivers the session-bound CSRF token.
type CSRFResponse struct {
	CSRFToken string `json:"csrf_token"`
}
