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
