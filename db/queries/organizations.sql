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

-- name: GetOrganizationForReview :one
SELECT id, org_type, legal_name, trade_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at, decision_reason, created_at, updated_at, deleted_at
FROM organizations
WHERE id = sqlc.arg('id')
  AND deleted_at IS NULL
FOR UPDATE;

-- name: ListOrganizationsFiltered :many
SELECT id, org_type, legal_name, trade_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at, decision_reason, created_at, updated_at, deleted_at
FROM organizations
WHERE (sqlc.narg('verification_status')::text IS NULL OR verification_status = sqlc.narg('verification_status'))
  AND (sqlc.narg('org_type')::text IS NULL OR org_type = sqlc.narg('org_type'))
  AND deleted_at IS NULL
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: CountOrganizationsFiltered :one
SELECT COUNT(*)
FROM organizations
WHERE (sqlc.narg('verification_status')::text IS NULL OR verification_status = sqlc.narg('verification_status'))
  AND (sqlc.narg('org_type')::text IS NULL OR org_type = sqlc.narg('org_type'))
  AND deleted_at IS NULL;

-- name: ListOrganizationsByUserID :many
SELECT o.id, o.org_type, o.legal_name, o.trade_name, o.country_code, o.registration_number, o.official_domain, o.verification_status, o.reviewed_by_user_id, o.reviewed_at, o.decision_reason, o.created_at, o.updated_at, o.deleted_at,
       om.id AS membership_id, om.role AS user_role, om.is_active AS user_is_active
FROM organizations o
JOIN organization_memberships om ON om.organization_id = o.id
WHERE om.user_id = sqlc.arg('user_id')
  AND o.deleted_at IS NULL
ORDER BY o.created_at DESC, o.id DESC;

-- name: ApproveOrganizationIfPending :one
UPDATE organizations
SET
    verification_status = 'VERIFIED',
    reviewed_by_user_id = sqlc.arg('reviewed_by_user_id'),
    reviewed_at = NOW(),
    decision_reason = sqlc.narg('decision_reason'),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND verification_status = 'PENDING'
  AND deleted_at IS NULL
RETURNING id, org_type, legal_name, trade_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at, decision_reason, created_at, updated_at, deleted_at;

-- name: RejectOrganizationIfPending :one
UPDATE organizations
SET
    verification_status = 'REJECTED',
    reviewed_by_user_id = sqlc.arg('reviewed_by_user_id'),
    reviewed_at = NOW(),
    decision_reason = sqlc.arg('decision_reason'),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND verification_status = 'PENDING'
  AND deleted_at IS NULL
RETURNING id, org_type, legal_name, trade_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at, decision_reason, created_at, updated_at, deleted_at;

-- name: UpdateOrganizationProfile :one
UPDATE organizations
SET
    trade_name = sqlc.arg('trade_name'),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND verification_status = 'VERIFIED'
  AND deleted_at IS NULL
RETURNING id, org_type, legal_name, trade_name, country_code, registration_number, official_domain, verification_status, reviewed_by_user_id, reviewed_at, decision_reason, created_at, updated_at, deleted_at;

-- name: ListPublicVerifiedOrganizations :many
SELECT id, org_type, legal_name, trade_name, country_code, official_domain, created_at
FROM organizations
WHERE verification_status = 'VERIFIED'
  AND (sqlc.narg('org_type')::text IS NULL OR org_type = sqlc.narg('org_type'))
  AND deleted_at IS NULL
ORDER BY legal_name ASC, id ASC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: CountPublicVerifiedOrganizations :one
SELECT COUNT(*)
FROM organizations
WHERE verification_status = 'VERIFIED'
  AND (sqlc.narg('org_type')::text IS NULL OR org_type = sqlc.narg('org_type'))
  AND deleted_at IS NULL;

-- name: GetPublicVerifiedOrganizationByID :one
SELECT id, org_type, legal_name, trade_name, country_code, official_domain, created_at
FROM organizations
WHERE id = sqlc.arg('id')
  AND verification_status = 'VERIFIED'
  AND deleted_at IS NULL;

-- name: CheckOrganizationConflict :one
SELECT EXISTS (
    SELECT 1 FROM organizations
    WHERE (
        LOWER(official_domain) = LOWER(sqlc.arg('official_domain')::text)
        OR (country_code = UPPER(sqlc.arg('country_code')::text) AND registration_number = UPPER(sqlc.arg('registration_number')::text))
    ) AND deleted_at IS NULL
) AS has_conflict;
