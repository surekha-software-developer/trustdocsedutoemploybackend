-- name: GetOrganizationByID :one
SELECT id, org_type, legal_name, trade_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at, decision_reason, created_at, updated_at, deleted_at
FROM organizations
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetOrganizationByDomain :one
SELECT id, org_type, legal_name, trade_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at, decision_reason, created_at, updated_at, deleted_at
FROM organizations
WHERE LOWER(official_domain) = LOWER($1) AND deleted_at IS NULL;

-- name: ListOrganizationsByStatus :many
SELECT id, org_type, legal_name, trade_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at, decision_reason, created_at, updated_at, deleted_at
FROM organizations
WHERE verification_status = $1 AND deleted_at IS NULL
ORDER BY created_at DESC;

-- name: CreateOrganization :one
INSERT INTO organizations (
    org_type, legal_name, trade_name, country_code, registration_number, official_domain, verification_status
) VALUES (
    $1, $2, $3, $4, $5, $6, 'PENDING'
)
RETURNING id, org_type, legal_name, trade_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at, decision_reason, created_at, updated_at, deleted_at;

-- name: ReviewOrganization :one
UPDATE organizations
SET
    verification_status = $2,
    reviewed_by_user_id = $3,
    reviewed_at = NOW(),
    decision_reason = $4,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
RETURNING id, org_type, legal_name, trade_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at, decision_reason, created_at, updated_at, deleted_at;

-- name: SoftDeleteOrganization :exec
UPDATE organizations
SET
    deleted_at = NOW(),
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL;
