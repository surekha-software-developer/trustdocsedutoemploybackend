BEGIN;

-- ============================================================================
-- 1. CERTIFICATES TABLE
-- ============================================================================
CREATE TABLE certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_id VARCHAR(64) NOT NULL,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    recipient_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    -- Recipient Snapshot
    recipient_name VARCHAR(255) NOT NULL,
    recipient_email VARCHAR(255) NOT NULL,
    student_id_number VARCHAR(100) NULL,

    -- Academic Credentials
    title VARCHAR(255) NOT NULL,
    degree_type VARCHAR(100) NOT NULL,
    major VARCHAR(255) NULL,
    grade_or_honors VARCHAR(100) NULL,
    graduation_date DATE NOT NULL,
    issue_date DATE NOT NULL,

    -- Lifecycle State
    status VARCHAR(50) NOT NULL DEFAULT 'DRAFT',

    -- Cloudflare R2 Document File & Cryptographic Integrity
    file_storage_key VARCHAR(512) NULL,
    file_name VARCHAR(255) NULL,
    file_size BIGINT NULL,
    file_mime_type VARCHAR(100) NULL,
    document_hash CHAR(64) NULL,

    -- Timestamps & Attribution
    created_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    issued_by_user_id UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    issued_at TIMESTAMPTZ NULL,

    -- Revocation & Replacement Lineage
    revoked_by_user_id UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    revoked_at TIMESTAMPTZ NULL,
    revocation_reason_code VARCHAR(100) NULL,
    revocation_reason TEXT NULL,
    replaced_by_certificate_id UUID NULL REFERENCES certificates(id) ON DELETE RESTRICT,
    replaces_certificate_id UUID NULL REFERENCES certificates(id) ON DELETE RESTRICT,

    -- Soft Deletion (Permitted ONLY for DRAFT certificates)
    deleted_at TIMESTAMPTZ NULL,

    -- Core Format Constraints
    CONSTRAINT chk_certificates_status CHECK (
        status IN ('DRAFT', 'ISSUED', 'REVOKED', 'REPLACED')
    ),
    CONSTRAINT chk_certificates_public_id_format CHECK (
        public_id ~ '^TD-CERT-[A-Z0-9]{16,32}$'
    ),
    CONSTRAINT chk_certificates_hash_format CHECK (
        document_hash IS NULL OR document_hash ~ '^[a-f0-9]{64}$'
    ),
    CONSTRAINT chk_certificates_degree_type_enum CHECK (
        degree_type IN ('BACHELOR', 'MASTER', 'DOCTORATE', 'DIPLOMA', 'ASSOCIATE', 'CERTIFICATE')
    ),

    -- Canonical and Non-Empty String Constraints
    CONSTRAINT chk_certificates_recipient_name_canonical CHECK (
        recipient_name = BTRIM(recipient_name) AND recipient_name <> ''
    ),
    CONSTRAINT chk_certificates_title_canonical CHECK (
        title = BTRIM(title) AND title <> ''
    ),
    CONSTRAINT chk_certificates_degree_type_canonical CHECK (
        degree_type = UPPER(BTRIM(degree_type)) AND degree_type <> ''
    ),
    CONSTRAINT chk_certificates_recipient_email_canonical CHECK (
        recipient_email = LOWER(BTRIM(recipient_email)) AND recipient_email <> ''
    ),
    CONSTRAINT chk_certificates_student_id_canonical CHECK (
        student_id_number IS NULL OR (student_id_number = BTRIM(student_id_number) AND student_id_number <> '')
    ),
    CONSTRAINT chk_certificates_file_name_canonical CHECK (
        file_name IS NULL OR (file_name = BTRIM(file_name) AND file_name <> '')
    ),
    CONSTRAINT chk_certificates_file_storage_key_canonical CHECK (
        file_storage_key IS NULL OR (file_storage_key = BTRIM(file_storage_key) AND file_storage_key <> '')
    ),
    CONSTRAINT chk_certificates_major_canonical CHECK (
        major IS NULL OR (major = BTRIM(major) AND major <> '')
    ),
    CONSTRAINT chk_certificates_grade_canonical CHECK (
        grade_or_honors IS NULL OR (grade_or_honors = BTRIM(grade_or_honors) AND grade_or_honors <> '')
    ),
    CONSTRAINT chk_certificates_revocation_reason_canonical CHECK (
        revocation_reason IS NULL OR (revocation_reason = BTRIM(revocation_reason) AND revocation_reason <> '')
    ),

    -- Academic Date Consistency (issue_date >= graduation_date; temporal ordering)
    CONSTRAINT chk_certificates_academic_dates CHECK (
        issue_date >= graduation_date AND
        (issued_at IS NULL OR issued_at >= created_at) AND
        (revoked_at IS NULL OR (issued_at IS NOT NULL AND revoked_at >= issued_at))
    ),

    -- File Storage Consistency (All file fields must be populated together or remain all NULL)
    CONSTRAINT chk_certificates_file_consistency CHECK (
        (file_storage_key IS NULL AND file_name IS NULL AND file_size IS NULL AND file_mime_type IS NULL AND document_hash IS NULL) OR
        (file_storage_key IS NOT NULL AND file_name IS NOT NULL AND file_size IS NOT NULL AND file_size > 0 AND file_size <= 10485760 AND file_mime_type = 'application/pdf' AND document_hash IS NOT NULL)
    ),

    -- Comprehensive State Invariant Consistency
    CONSTRAINT chk_certificates_status_consistency CHECK (
        (status = 'DRAFT' AND
         issued_at IS NULL AND
         issued_by_user_id IS NULL AND
         revoked_at IS NULL AND
         revoked_by_user_id IS NULL AND
         revocation_reason_code IS NULL AND
         revocation_reason IS NULL AND
         replaced_by_certificate_id IS NULL AND
         replaces_certificate_id IS NULL)
        OR
        (status = 'ISSUED' AND
         issued_at IS NOT NULL AND
         issued_by_user_id IS NOT NULL AND
         document_hash IS NOT NULL AND
         file_storage_key IS NOT NULL AND
         revoked_at IS NULL AND
         revoked_by_user_id IS NULL AND
         revocation_reason_code IS NULL AND
         revocation_reason IS NULL AND
         replaced_by_certificate_id IS NULL AND
         deleted_at IS NULL)
        OR
        (status = 'REVOKED' AND
         issued_at IS NOT NULL AND
         issued_by_user_id IS NOT NULL AND
         document_hash IS NOT NULL AND
         file_storage_key IS NOT NULL AND
         revoked_at IS NOT NULL AND
         revoked_by_user_id IS NOT NULL AND
         revocation_reason_code IS NOT NULL AND
         revocation_reason IS NOT NULL AND
         replaced_by_certificate_id IS NULL AND
         deleted_at IS NULL)
        OR
        (status = 'REPLACED' AND
         issued_at IS NOT NULL AND
         issued_by_user_id IS NOT NULL AND
         document_hash IS NOT NULL AND
         file_storage_key IS NOT NULL AND
         revoked_at IS NOT NULL AND
         revoked_by_user_id IS NOT NULL AND
         revocation_reason_code IS NOT NULL AND
         revocation_reason IS NOT NULL AND
         replaced_by_certificate_id IS NOT NULL AND
         deleted_at IS NULL)
    ),

    -- Self-Replacement and Direct Cycle Prevention
    CONSTRAINT chk_certificates_no_self_replacement CHECK (
        (replaced_by_certificate_id IS NULL OR replaced_by_certificate_id != id) AND
        (replaces_certificate_id IS NULL OR replaces_certificate_id != id)
    ),
    CONSTRAINT chk_certificates_no_direct_cycle CHECK (
        replaced_by_certificate_id IS NULL OR replaces_certificate_id IS NULL OR replaced_by_certificate_id != replaces_certificate_id
    ),

    CONSTRAINT uq_certificates_public_id UNIQUE (public_id)
);

-- Cryptographic Document Hash Uniqueness (No two issued, revoked, or replaced certificates may claim identical document bytes)
CREATE UNIQUE INDEX idx_certificates_document_hash_finalized ON certificates (document_hash)
    WHERE status IN ('ISSUED', 'REVOKED', 'REPLACED') AND deleted_at IS NULL;

-- Strict 1-to-1 Replacement Lineage Indexes
CREATE UNIQUE INDEX idx_certificates_replaced_by ON certificates (replaced_by_certificate_id)
    WHERE replaced_by_certificate_id IS NOT NULL;
CREATE UNIQUE INDEX idx_certificates_replaces ON certificates (replaces_certificate_id)
    WHERE replaces_certificate_id IS NOT NULL;

-- Query & Multi-Tenant Performance Indexes
CREATE INDEX idx_certificates_org_status ON certificates (organization_id, status, created_at DESC)
    WHERE deleted_at IS NULL;
CREATE INDEX idx_certificates_recipient ON certificates (recipient_user_id, status, created_at DESC)
    WHERE deleted_at IS NULL;
CREATE INDEX idx_certificates_public_id ON certificates (public_id)
    WHERE deleted_at IS NULL;

COMMIT;
