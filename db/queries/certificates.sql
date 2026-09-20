-- ============================================================================
-- Certificates Domain sqlc Queries (Phase 5A)
-- ============================================================================

-- name: CreateCertificateDraft :one
INSERT INTO certificates (
    public_id, organization_id, recipient_user_id, recipient_name, recipient_email,
    student_id_number, title, degree_type, major, grade_or_honors, graduation_date,
    issue_date, status, created_by_user_id
) VALUES (
    sqlc.arg('public_id'), sqlc.arg('organization_id'), sqlc.arg('recipient_user_id'),
    sqlc.arg('recipient_name'), sqlc.arg('recipient_email'), sqlc.narg('student_id_number'),
    sqlc.arg('title'), sqlc.arg('degree_type'), sqlc.narg('major'), sqlc.narg('grade_or_honors'),
    sqlc.arg('graduation_date'), sqlc.arg('issue_date'), 'DRAFT', sqlc.arg('created_by_user_id')
)
RETURNING *;

-- name: UpdateCertificateDraft :one
UPDATE certificates
SET
    recipient_user_id = COALESCE(sqlc.narg('recipient_user_id'), recipient_user_id),
    recipient_name = COALESCE(sqlc.narg('recipient_name'), recipient_name),
    recipient_email = COALESCE(sqlc.narg('recipient_email'), recipient_email),
    student_id_number = COALESCE(sqlc.narg('student_id_number'), student_id_number),
    title = COALESCE(sqlc.narg('title'), title),
    degree_type = COALESCE(sqlc.narg('degree_type'), degree_type),
    major = COALESCE(sqlc.narg('major'), major),
    grade_or_honors = COALESCE(sqlc.narg('grade_or_honors'), grade_or_honors),
    graduation_date = COALESCE(sqlc.narg('graduation_date'), graduation_date),
    issue_date = COALESCE(sqlc.narg('issue_date'), issue_date),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND organization_id = sqlc.arg('organization_id')
  AND status = 'DRAFT'
  AND deleted_at IS NULL
RETURNING *;

-- name: AttachCertificateFile :one
UPDATE certificates
SET
    file_storage_key = sqlc.arg('file_storage_key'),
    file_name = sqlc.arg('file_name'),
    file_size = sqlc.arg('file_size'),
    file_mime_type = sqlc.arg('file_mime_type'),
    document_hash = sqlc.arg('document_hash'),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND organization_id = sqlc.arg('organization_id')
  AND status = 'DRAFT'
  AND deleted_at IS NULL
RETURNING *;

-- name: GetCertificateByIDForUpdate :one
SELECT * FROM certificates
WHERE id = sqlc.arg('id')
  AND organization_id = sqlc.arg('organization_id')
  AND deleted_at IS NULL
FOR UPDATE;

-- name: IssueCertificate :one
UPDATE certificates
SET
    status = 'ISSUED',
    issued_by_user_id = sqlc.arg('issued_by_user_id'),
    issued_at = NOW(),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND organization_id = sqlc.arg('organization_id')
  AND status = 'DRAFT'
  AND issue_date <= CURRENT_DATE
  AND file_storage_key IS NOT NULL
  AND document_hash IS NOT NULL
  AND replaces_certificate_id IS NULL
  AND replaced_by_certificate_id IS NULL
  AND deleted_at IS NULL
RETURNING *;

-- name: IssueReplacementCertificate :one
UPDATE certificates
SET
    status = 'ISSUED',
    issued_by_user_id = sqlc.arg('issued_by_user_id'),
    issued_at = NOW(),
    replaces_certificate_id = sqlc.arg('replaces_certificate_id'),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND organization_id = sqlc.arg('organization_id')
  AND status = 'DRAFT'
  AND deleted_at IS NULL
  AND replaces_certificate_id IS NULL
  AND replaced_by_certificate_id IS NULL
  AND file_storage_key IS NOT NULL
  AND document_hash IS NOT NULL
  AND issue_date <= CURRENT_DATE
  AND id <> sqlc.arg('replaces_certificate_id')
RETURNING *;

-- name: RevokeCertificate :one
UPDATE certificates
SET
    status = 'REVOKED',
    revoked_by_user_id = sqlc.arg('revoked_by_user_id'),
    revoked_at = NOW(),
    revocation_reason_code = sqlc.arg('revocation_reason_code'),
    revocation_reason = sqlc.arg('revocation_reason'),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND organization_id = sqlc.arg('organization_id')
  AND status = 'ISSUED'
  AND deleted_at IS NULL
RETURNING *;

-- name: MarkCertificateReplaced :one
UPDATE certificates
SET
    status = 'REPLACED',
    revoked_by_user_id = sqlc.arg('revoked_by_user_id'),
    revoked_at = NOW(),
    revocation_reason_code = sqlc.arg('revocation_reason_code'),
    revocation_reason = sqlc.arg('revocation_reason'),
    replaced_by_certificate_id = sqlc.arg('replaced_by_certificate_id'),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND organization_id = sqlc.arg('organization_id')
  AND status = 'ISSUED'
  AND replaced_by_certificate_id IS NULL
  AND deleted_at IS NULL
  AND id <> sqlc.arg('replaced_by_certificate_id')
RETURNING *;

-- name: GetCertificateByID :one
SELECT * FROM certificates
WHERE id = sqlc.arg('id')
  AND organization_id = sqlc.arg('organization_id')
  AND deleted_at IS NULL;

-- name: GetCertificateByPublicID :one
SELECT c.id, c.public_id, c.status, c.title, c.degree_type, c.major,
       c.graduation_date, c.issue_date, c.document_hash, c.revocation_reason_code,
       c.revoked_at, c.recipient_name,
       o.legal_name AS issuer_organization_name,
       o.official_domain AS issuer_organization_domain,
       o.country_code AS issuer_country_code,
       rep.public_id AS replaced_by_public_id
FROM certificates c
JOIN organizations o ON o.id = c.organization_id
LEFT JOIN certificates rep ON rep.id = c.replaced_by_certificate_id
WHERE c.public_id = sqlc.arg('public_id')
  AND c.status IN ('ISSUED', 'REVOKED', 'REPLACED')
  AND c.deleted_at IS NULL
  AND o.deleted_at IS NULL;

-- name: ListCertificatesByOrganization :many
SELECT * FROM certificates
WHERE organization_id = sqlc.arg('organization_id')
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
  AND (sqlc.narg('recipient_email')::text IS NULL OR recipient_email = LOWER(sqlc.narg('recipient_email')))
  AND deleted_at IS NULL
ORDER BY created_at DESC, id ASC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: CountCertificatesByOrganization :one
SELECT COUNT(*) FROM certificates
WHERE organization_id = sqlc.arg('organization_id')
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
  AND (sqlc.narg('recipient_email')::text IS NULL OR recipient_email = LOWER(sqlc.narg('recipient_email')))
  AND deleted_at IS NULL;

-- name: ListCertificatesByRecipient :many
SELECT c.*, o.legal_name AS organization_legal_name, o.official_domain AS organization_domain
FROM certificates c
JOIN organizations o ON o.id = c.organization_id
WHERE c.recipient_user_id = sqlc.arg('recipient_user_id')
  AND c.status IN ('ISSUED', 'REVOKED', 'REPLACED')
  AND (sqlc.narg('status')::text IS NULL OR c.status = sqlc.narg('status'))
  AND c.deleted_at IS NULL
  AND o.deleted_at IS NULL
ORDER BY c.issue_date DESC, c.id ASC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: CountCertificatesByRecipient :one
SELECT COUNT(*) FROM certificates c
JOIN organizations o ON o.id = c.organization_id
WHERE c.recipient_user_id = sqlc.arg('recipient_user_id')
  AND c.status IN ('ISSUED', 'REVOKED', 'REPLACED')
  AND (sqlc.narg('status')::text IS NULL OR c.status = sqlc.narg('status'))
  AND c.deleted_at IS NULL
  AND o.deleted_at IS NULL;

-- name: DeleteCertificateDraft :one
UPDATE certificates
SET deleted_at = NOW(), updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND organization_id = sqlc.arg('organization_id')
  AND status = 'DRAFT'
  AND deleted_at IS NULL
RETURNING id, file_storage_key;

-- name: CheckDocumentHashConflict :one
SELECT EXISTS (
    SELECT 1 FROM certificates
    WHERE document_hash = sqlc.arg('document_hash')
      AND status IN ('ISSUED', 'REVOKED', 'REPLACED')
      AND deleted_at IS NULL
);
