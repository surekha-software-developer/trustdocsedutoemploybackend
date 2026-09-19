-- name: GetMembership :one
SELECT id, organization_id, user_id, role, is_active, created_at, updated_at
FROM organization_memberships
WHERE organization_id = $1 AND user_id = $2;

-- name: ListMembershipsByUserID :many
SELECT om.id, om.organization_id, om.user_id, om.role, om.is_active, om.created_at, om.updated_at,
       o.legal_name AS organization_legal_name, o.org_type AS organization_type, o.verification_status AS organization_status
FROM organization_memberships om
JOIN organizations o ON o.id = om.organization_id
WHERE om.user_id = $1 AND om.is_active = TRUE AND o.deleted_at IS NULL
ORDER BY om.created_at ASC;

-- name: ListMembershipsByOrgID :many
SELECT om.id, om.organization_id, om.user_id, om.role, om.is_active, om.created_at, om.updated_at,
       u.email AS user_email, u.full_name AS user_full_name
FROM organization_memberships om
JOIN users u ON u.id = om.user_id
WHERE om.organization_id = $1 AND u.deleted_at IS NULL
ORDER BY om.created_at ASC;

-- name: CreateMembership :one
INSERT INTO organization_memberships (
    organization_id, user_id, role, is_active
) VALUES (
    $1, $2, $3, $4
)
RETURNING id, organization_id, user_id, role, is_active, created_at, updated_at;

-- name: UpdateMembershipRole :one
UPDATE organization_memberships
SET
    role = $3,
    is_active = $4,
    updated_at = NOW()
WHERE organization_id = $1 AND user_id = $2
RETURNING id, organization_id, user_id, role, is_active, created_at, updated_at;

-- name: CreatePendingOrganizationAdminMembership :one
INSERT INTO organization_memberships (
    organization_id, user_id, role, is_active
) VALUES (
    sqlc.arg('organization_id'),
    sqlc.arg('user_id'),
    sqlc.arg('role'),
    FALSE
)
RETURNING id, organization_id, user_id, role, is_active, created_at, updated_at;

-- name: ListMembershipsByOrgIDForReview :many
SELECT id, organization_id, user_id, role, is_active, created_at, updated_at
FROM organization_memberships
WHERE organization_id = sqlc.arg('organization_id')
FOR UPDATE;

-- name: ActivateOrganizationAdminMembership :one
UPDATE organization_memberships
SET
    is_active = TRUE,
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND organization_id = sqlc.arg('organization_id')
  AND user_id = sqlc.arg('user_id')
  AND role = sqlc.arg('role')
  AND is_active = FALSE
RETURNING id, organization_id, user_id, role, is_active, created_at, updated_at;

-- name: ListMembershipsByOrgIDWithUser :many
SELECT om.id AS membership_id, om.organization_id, om.user_id, om.role, om.is_active, om.created_at AS membership_created_at,
       u.full_name AS user_full_name, u.email AS user_email
FROM organization_memberships om
JOIN users u ON u.id = om.user_id
WHERE om.organization_id = sqlc.arg('organization_id')
  AND u.deleted_at IS NULL
ORDER BY om.created_at ASC, om.id ASC;

-- name: ListActiveOrganizationMembers :many
SELECT om.id, om.organization_id, om.user_id, om.role, om.is_active, om.created_at, om.updated_at,
       u.full_name AS user_full_name, u.email AS user_email
FROM organization_memberships om
JOIN users u ON u.id = om.user_id
WHERE om.organization_id = sqlc.arg('organization_id')
  AND om.is_active = TRUE
  AND (sqlc.narg('role')::text IS NULL OR om.role = sqlc.narg('role'))
  AND u.deleted_at IS NULL
ORDER BY om.created_at ASC, om.id ASC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: CountActiveOrganizationMembers :one
SELECT COUNT(*)
FROM organization_memberships om
JOIN users u ON u.id = om.user_id
WHERE om.organization_id = sqlc.arg('organization_id')
  AND om.is_active = TRUE
  AND (sqlc.narg('role')::text IS NULL OR om.role = sqlc.narg('role'))
  AND u.deleted_at IS NULL;
