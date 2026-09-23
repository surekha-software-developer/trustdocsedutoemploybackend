BEGIN;

-- ============================================================================
-- 1. MERKLE BATCHES TABLE
-- ============================================================================
-- merkle_batches manages the lifecycle of cryptographic anchoring batches:
-- BUILDING -> READY -> SUBMITTING -> SUBMITTED -> CONFIRMED (or FAILED).
--
-- Authoritative transaction reference:
-- authoritative_transaction_id replaces duplicated tx_hash and points to
-- the definitive blockchain_transactions attempt for this batch.
--
-- SUBMITTING two-substate lifecycle note:
-- SUBMITTING represents two valid operational substates:
--   1. Leased but transaction not yet prepared in database:
--      authoritative_transaction_id IS NULL
--   2. Prepared in database before network broadcast:
--      authoritative_transaction_id IS NOT NULL
-- In both substates: submitted_at IS NULL, block fields are NULL,
-- confirmation_count = 0, and failure fields are NULL.
--
-- Cross-table attempt status note:
-- PostgreSQL CHECK constraints cannot query foreign tables. Cross-table attempt-status
-- compatibility (e.g. ensuring authoritative_transaction_id is in PREPARED or BROADCAST
-- during SUBMITTING/SUBMITTED, or FAILED/PREPARED on SUBMISSION failure) is enforced
-- transactionally in repository/worker code and documented here.
-- ============================================================================
CREATE TABLE merkle_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_number BIGSERIAL NOT NULL UNIQUE,
    canonical_batch_id CHAR(66) NOT NULL UNIQUE, -- '0x' + 64 lowercase hex (bytes32)
    status VARCHAR(50) NOT NULL DEFAULT 'BUILDING',

    -- Cryptographic Specification Versioning
    tree_algorithm VARCHAR(50) NOT NULL DEFAULT 'TD-MERKLE-KECCAK256-V1',
    tree_version INT NOT NULL DEFAULT 1,
    leaf_encoding_version VARCHAR(50) NOT NULL DEFAULT 'TD-LEAF-V1',
    proof_format_version VARCHAR(50) NOT NULL DEFAULT 'TD-PROOF-SORTED-V1',

    -- Merkle Root & Leaf Metrics
    merkle_root CHAR(66) NULL, -- '0x' + 64 lowercase hex
    leaf_count INT NOT NULL DEFAULT 0,

    -- Worker Submission Lease (Crash-Safe Distributed Locking)
    claimed_by VARCHAR(100) NULL,
    claim_expires_at TIMESTAMPTZ NULL,

    -- Authoritative Transaction Reference (Eliminates tx_hash duplication)
    authoritative_transaction_id UUID NULL,

    -- Blockchain Anchor Attribution
    chain_id BIGINT NULL,
    contract_address CHAR(42) NULL, -- '0x' + 40 lowercase hex
    block_number BIGINT NULL,
    block_hash CHAR(66) NULL,        -- '0x' + 64 lowercase hex
    confirmation_count INT NOT NULL DEFAULT 0,

    -- Failure & Retry Tracking
    retry_count INT NOT NULL DEFAULT 0,
    failure_stage VARCHAR(50) NULL,      -- 'BUILD', 'SUBMISSION', 'CONFIRMATION'
    failure_code VARCHAR(100) NULL,       -- allowlisted failure code
    failure_detail_code VARCHAR(100) NULL, -- allowlisted categorized detail code

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ready_at TIMESTAMPTZ NULL,
    submitted_at TIMESTAMPTZ NULL,
    confirmed_at TIMESTAMPTZ NULL,
    failed_at TIMESTAMPTZ NULL,

    -- Format Constraints
    CONSTRAINT chk_merkle_batches_status CHECK (
        status IN ('BUILDING', 'READY', 'SUBMITTING', 'SUBMITTED', 'CONFIRMED', 'FAILED')
    ),
    CONSTRAINT chk_merkle_batches_canonical_id CHECK (
        canonical_batch_id ~ '^0x[0-9a-f]{64}$'
    ),
    CONSTRAINT chk_merkle_batches_root_format CHECK (
        merkle_root IS NULL OR merkle_root ~ '^0x[0-9a-f]{64}$'
    ),
    CONSTRAINT chk_merkle_batches_contract_format CHECK (
        contract_address IS NULL OR contract_address ~ '^0x[0-9a-f]{40}$'
    ),
    CONSTRAINT chk_merkle_batches_block_hash_format CHECK (
        block_hash IS NULL OR block_hash ~ '^0x[0-9a-f]{64}$'
    ),
    CONSTRAINT chk_merkle_batches_failure_stage CHECK (
        failure_stage IS NULL OR failure_stage IN ('BUILD', 'SUBMISSION', 'CONFIRMATION')
    ),
    CONSTRAINT chk_merkle_batches_metrics_positive CHECK (
        leaf_count >= 0 AND retry_count >= 0 AND confirmation_count >= 0
    ),

    -- Exhaustive Status Invariant Consistency
    CONSTRAINT chk_merkle_batches_status_consistency CHECK (
        (status = 'BUILDING' AND
         merkle_root IS NULL AND
         leaf_count = 0 AND
         ready_at IS NULL AND
         claimed_by IS NULL AND
         claim_expires_at IS NULL AND
         authoritative_transaction_id IS NULL AND
         chain_id IS NULL AND
         contract_address IS NULL AND
         block_number IS NULL AND
         block_hash IS NULL AND
         confirmation_count = 0 AND
         submitted_at IS NULL AND
         confirmed_at IS NULL AND
         failed_at IS NULL AND
         failure_stage IS NULL AND
         failure_code IS NULL AND
         failure_detail_code IS NULL)
        OR
        (status = 'READY' AND
         merkle_root IS NOT NULL AND
         leaf_count > 0 AND
         ready_at IS NOT NULL AND
         claimed_by IS NULL AND
         claim_expires_at IS NULL AND
         authoritative_transaction_id IS NULL AND
         chain_id IS NULL AND
         contract_address IS NULL AND
         block_number IS NULL AND
         block_hash IS NULL AND
         confirmation_count = 0 AND
         submitted_at IS NULL AND
         confirmed_at IS NULL AND
         failed_at IS NULL AND
         failure_stage IS NULL AND
         failure_code IS NULL AND
         failure_detail_code IS NULL)
        OR
        (status = 'SUBMITTING' AND
         merkle_root IS NOT NULL AND
         leaf_count > 0 AND
         ready_at IS NOT NULL AND
         claimed_by IS NOT NULL AND
         claim_expires_at IS NOT NULL AND
         chain_id IS NOT NULL AND
         contract_address IS NOT NULL AND
         block_number IS NULL AND
         block_hash IS NULL AND
         confirmation_count = 0 AND
         submitted_at IS NULL AND
         confirmed_at IS NULL AND
         failed_at IS NULL AND
         failure_stage IS NULL AND
         failure_code IS NULL AND
         failure_detail_code IS NULL)
        OR
        (status = 'SUBMITTED' AND
         merkle_root IS NOT NULL AND
         leaf_count > 0 AND
         ready_at IS NOT NULL AND
         claimed_by IS NULL AND
         claim_expires_at IS NULL AND
         authoritative_transaction_id IS NOT NULL AND
         chain_id IS NOT NULL AND
         contract_address IS NOT NULL AND
         submitted_at IS NOT NULL AND
         block_number IS NULL AND
         block_hash IS NULL AND
         confirmation_count = 0 AND
         confirmed_at IS NULL AND
         failed_at IS NULL AND
         failure_stage IS NULL AND
         failure_code IS NULL AND
         failure_detail_code IS NULL)
        OR
        (status = 'CONFIRMED' AND
         merkle_root IS NOT NULL AND
         leaf_count > 0 AND
         ready_at IS NOT NULL AND
         claimed_by IS NULL AND
         claim_expires_at IS NULL AND
         authoritative_transaction_id IS NOT NULL AND
         chain_id IS NOT NULL AND
         contract_address IS NOT NULL AND
         block_number IS NOT NULL AND
         block_hash IS NOT NULL AND
         submitted_at IS NOT NULL AND
         confirmed_at IS NOT NULL AND
         confirmed_at >= submitted_at AND
         confirmation_count >= 1 AND
         failed_at IS NULL AND
         failure_stage IS NULL AND
         failure_code IS NULL AND
         failure_detail_code IS NULL)
        OR
        -- FAILED Stage 1: BUILD Failure (failure before Merkle tree finalized)
        (status = 'FAILED' AND
         failure_stage = 'BUILD' AND
         merkle_root IS NULL AND
         leaf_count = 0 AND
         ready_at IS NULL AND
         claimed_by IS NULL AND
         claim_expires_at IS NULL AND
         authoritative_transaction_id IS NULL AND
         chain_id IS NULL AND
         contract_address IS NULL AND
         block_number IS NULL AND
         block_hash IS NULL AND
         confirmation_count = 0 AND
         submitted_at IS NULL AND
         confirmed_at IS NULL AND
         failed_at IS NOT NULL AND
         failure_code IS NOT NULL AND
         failure_detail_code IS NOT NULL)
        OR
        -- FAILED Stage 2: SUBMISSION Failure (tree exists; lease released; tx failed or not prepared)
        (status = 'FAILED' AND
         failure_stage = 'SUBMISSION' AND
         merkle_root IS NOT NULL AND
         leaf_count > 0 AND
         ready_at IS NOT NULL AND
         claimed_by IS NULL AND
         claim_expires_at IS NULL AND
         chain_id IS NOT NULL AND
         contract_address IS NOT NULL AND
         block_number IS NULL AND
         block_hash IS NULL AND
         confirmation_count = 0 AND
         submitted_at IS NULL AND
         confirmed_at IS NULL AND
         failed_at IS NOT NULL AND
         failure_code IS NOT NULL AND
         failure_detail_code IS NOT NULL)
        OR
        -- FAILED Stage 3: CONFIRMATION Failure (broadcast succeeded; reverted or permanently dropped)
        (status = 'FAILED' AND
         failure_stage = 'CONFIRMATION' AND
         merkle_root IS NOT NULL AND
         leaf_count > 0 AND
         ready_at IS NOT NULL AND
         claimed_by IS NULL AND
         claim_expires_at IS NULL AND
         authoritative_transaction_id IS NOT NULL AND
         chain_id IS NOT NULL AND
         contract_address IS NOT NULL AND
         submitted_at IS NOT NULL AND
         block_number IS NULL AND
         block_hash IS NULL AND
         confirmed_at IS NULL AND
         failed_at IS NOT NULL AND
         failure_code IS NOT NULL AND
         failure_detail_code IS NOT NULL)
    )
);

-- ============================================================================
-- 2. BATCH CERTIFICATES TABLE (LEAF MAPPINGS & IMMUTABLE SNAPSHOTS)
-- ============================================================================
CREATE TABLE batch_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES merkle_batches(id) ON DELETE RESTRICT,
    certificate_id UUID NOT NULL REFERENCES certificates(id) ON DELETE RESTRICT,
    leaf_index INT NOT NULL,
    leaf_hash CHAR(66) NOT NULL, -- '0x' + 64 lowercase hex
    proof_depth INT NOT NULL,

    -- Immutable Verification Snapshot (precludes reliance on mutable joins)
    public_id VARCHAR(64) NOT NULL,
    document_hash CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT chk_batch_certificates_leaf_format CHECK (
        leaf_hash ~ '^0x[0-9a-f]{64}$'
    ),
    CONSTRAINT chk_batch_certificates_public_id_format CHECK (
        public_id ~ '^TD-CERT-[A-Z0-9]{16,32}$'
    ),
    CONSTRAINT chk_batch_certificates_doc_hash_format CHECK (
        document_hash ~ '^[a-f0-9]{64}$'
    ),
    CONSTRAINT chk_batch_certificates_index_positive CHECK (
        leaf_index >= 0
    ),
    CONSTRAINT chk_batch_certificates_depth_bounds CHECK (
        proof_depth >= 0 AND proof_depth <= 20
    ),

    -- Unique Enforcements
    CONSTRAINT uq_batch_certificates_certificate UNIQUE (certificate_id),
    CONSTRAINT uq_batch_certificates_batch_index UNIQUE (batch_id, leaf_index),
    CONSTRAINT uq_batch_certificates_batch_leaf UNIQUE (batch_id, leaf_hash)
);

-- ============================================================================
-- 3. BATCH CERTIFICATE PROOF NODES (NORMALIZED SIBLING STORAGE)
-- ============================================================================
CREATE TABLE batch_certificate_proof_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_certificate_id UUID NOT NULL REFERENCES batch_certificates(id) ON DELETE RESTRICT,
    proof_index INT NOT NULL,
    sibling_hash CHAR(66) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_proof_nodes_sibling_format CHECK (
        sibling_hash ~ '^0x[0-9a-f]{64}$'
    ),
    CONSTRAINT chk_proof_nodes_index_bounds CHECK (
        proof_index >= 0 AND proof_index < 20
    ),
    CONSTRAINT uq_proof_nodes_index UNIQUE (batch_certificate_id, proof_index)
);

-- ============================================================================
-- 4. SIGNER NONCE RESERVATIONS TABLE (AUTHORITATIVE NONCE ALLOCATION)
-- ============================================================================
CREATE TABLE signer_nonce_reservations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES merkle_batches(id) ON DELETE RESTRICT,
    chain_id BIGINT NOT NULL,
    signer_address CHAR(42) NOT NULL,
    nonce BIGINT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'COMMITTED', 'RELEASED'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    committed_at TIMESTAMPTZ NULL,

    CONSTRAINT chk_nonce_reservations_status CHECK (
        status IN ('ACTIVE', 'COMMITTED', 'RELEASED')
    ),
    CONSTRAINT chk_nonce_reservations_address CHECK (
        signer_address ~ '^0x[0-9a-f]{40}$'
    ),
    CONSTRAINT chk_nonce_reservations_nonce CHECK (nonce >= 0),
    CONSTRAINT uq_signer_nonce_reservations_slot UNIQUE (chain_id, signer_address, nonce),
    CONSTRAINT uq_signer_nonce_reservations_composite UNIQUE (id, batch_id, chain_id, signer_address, nonce)
);

-- ============================================================================
-- 5. BLOCKCHAIN TRANSACTIONS TABLE (ATTEMPTS & REPLACEMENTS)
-- ============================================================================
CREATE TABLE blockchain_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES merkle_batches(id) ON DELETE RESTRICT,
    nonce_reservation_id UUID NOT NULL REFERENCES signer_nonce_reservations(id) ON DELETE RESTRICT,
    replacement_sequence INT NOT NULL DEFAULT 0,

    -- Transaction Identification & Reconstruction Payload
    chain_id BIGINT NOT NULL,
    from_address CHAR(42) NOT NULL,
    to_address CHAR(42) NOT NULL,
    nonce BIGINT NOT NULL,
    transaction_type INT NOT NULL DEFAULT 2, -- EIP-1559 dynamic fee
    value_wei NUMERIC(78, 0) NOT NULL DEFAULT 0,
    calldata BYTEA NOT NULL,
    gas_limit BIGINT NOT NULL,
    max_fee_per_gas_wei NUMERIC(78, 0) NOT NULL,
    max_priority_fee_per_gas_wei NUMERIC(78, 0) NOT NULL,
    tx_hash CHAR(66) NOT NULL UNIQUE,

    -- Lifecycle State
    status VARCHAR(50) NOT NULL DEFAULT 'PREPARED',
    block_number BIGINT NULL,
    block_hash CHAR(66) NULL,
    gas_used BIGINT NULL,

    -- Replacement Lineage
    replaces_transaction_id UUID NULL REFERENCES blockchain_transactions(id) ON DELETE RESTRICT,

    -- Sanitized Error Codes
    failure_code VARCHAR(100) NULL,
    failure_detail_code VARCHAR(100) NULL,

    -- Timestamps
    prepared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    broadcast_at TIMESTAMPTZ NULL,
    mined_at TIMESTAMPTZ NULL,
    replaced_at TIMESTAMPTZ NULL,
    failed_at TIMESTAMPTZ NULL,

    -- Constraints
    CONSTRAINT chk_blockchain_tx_status CHECK (
        status IN ('PREPARED', 'BROADCAST', 'MINED', 'REPLACED', 'FAILED')
    ),
    CONSTRAINT chk_blockchain_tx_hash_format CHECK (
        tx_hash ~ '^0x[0-9a-f]{64}$'
    ),
    CONSTRAINT chk_blockchain_tx_block_hash CHECK (
        block_hash IS NULL OR block_hash ~ '^0x[0-9a-f]{64}$'
    ),
    CONSTRAINT chk_blockchain_tx_from_format CHECK (
        from_address ~ '^0x[0-9a-f]{40}$'
    ),
    CONSTRAINT chk_blockchain_tx_to_format CHECK (
        to_address ~ '^0x[0-9a-f]{40}$'
    ),
    CONSTRAINT chk_blockchain_tx_nonce CHECK (nonce >= 0),
    CONSTRAINT chk_blockchain_tx_gas_limit CHECK (gas_limit > 0),
    CONSTRAINT chk_blockchain_tx_fees CHECK (
        max_fee_per_gas_wei > 0 AND max_priority_fee_per_gas_wei >= 0 AND max_fee_per_gas_wei >= max_priority_fee_per_gas_wei
    ),
    CONSTRAINT chk_blockchain_tx_replacement_seq CHECK (replacement_sequence >= 0),

    -- Exhaustive Transaction State Check Constraints
    CONSTRAINT chk_blockchain_tx_status_consistency CHECK (
        (status = 'PREPARED' AND
         prepared_at IS NOT NULL AND
         broadcast_at IS NULL AND
         mined_at IS NULL AND
         replaced_at IS NULL AND
         failed_at IS NULL AND
         block_number IS NULL AND
         block_hash IS NULL AND
         gas_used IS NULL AND
         failure_code IS NULL AND
         failure_detail_code IS NULL)
        OR
        (status = 'BROADCAST' AND
         prepared_at IS NOT NULL AND
         broadcast_at IS NOT NULL AND
         broadcast_at >= prepared_at AND
         mined_at IS NULL AND
         replaced_at IS NULL AND
         failed_at IS NULL AND
         block_number IS NULL AND
         block_hash IS NULL AND
         gas_used IS NULL AND
         failure_code IS NULL AND
         failure_detail_code IS NULL)
        OR
        (status = 'MINED' AND
         prepared_at IS NOT NULL AND
         broadcast_at IS NOT NULL AND
         mined_at IS NOT NULL AND
         mined_at >= broadcast_at AND
         replaced_at IS NULL AND
         failed_at IS NULL AND
         block_number IS NOT NULL AND
         block_hash IS NOT NULL AND
         gas_used IS NOT NULL AND
         failure_code IS NULL AND
         failure_detail_code IS NULL)
        OR
        (status = 'REPLACED' AND
         prepared_at IS NOT NULL AND
         replaced_at IS NOT NULL AND
         replaced_at >= prepared_at AND
         mined_at IS NULL AND
         block_number IS NULL AND
         block_hash IS NULL AND
         gas_used IS NULL)
        OR
        (status = 'FAILED' AND
         prepared_at IS NOT NULL AND
         failed_at IS NOT NULL AND
         failure_code IS NOT NULL AND
         mined_at IS NULL AND
         block_number IS NULL AND
         block_hash IS NULL)
    ),

    -- Unique sequence per nonce reservation
    CONSTRAINT uq_blockchain_tx_reservation_seq UNIQUE (nonce_reservation_id, replacement_sequence),
    CONSTRAINT uq_blockchain_transactions_id_batch UNIQUE (id, batch_id),

    -- Composite FK Guarantee: An attempt CANNOT reference a reservation of another batch, chain, signer, or nonce!
    CONSTRAINT fk_blockchain_transactions_reservation_composite
        FOREIGN KEY (nonce_reservation_id, batch_id, chain_id, from_address, nonce)
        REFERENCES signer_nonce_reservations (id, batch_id, chain_id, signer_address, nonce)
        ON DELETE RESTRICT
);

-- Partial Unique Index: Exactly one active attempt (PREPARED or BROADCAST) per nonce reservation
CREATE UNIQUE INDEX uq_blockchain_tx_active_attempt
ON blockchain_transactions (nonce_reservation_id)
WHERE status IN ('PREPARED', 'BROADCAST');

-- ============================================================================
-- 6. CIRCULAR FOREIGN KEY LINK (BATCH -> AUTHORITATIVE TRANSACTION)
-- ============================================================================
-- Cross-Table Composite Constraint: merkle_batches.authoritative_transaction_id must belong to the SAME batch!
ALTER TABLE merkle_batches
    ADD CONSTRAINT fk_merkle_batches_authoritative_tx
    FOREIGN KEY (authoritative_transaction_id, id)
    REFERENCES blockchain_transactions (id, batch_id)
    ON DELETE RESTRICT;

-- ============================================================================
-- 7. OPTIMIZED INDEXES
-- ============================================================================
CREATE INDEX idx_merkle_batches_status_claim ON merkle_batches (status, claim_expires_at, created_at ASC);
CREATE INDEX idx_batch_certificates_batch_ordered ON batch_certificates (batch_id, leaf_index ASC);
CREATE INDEX idx_proof_nodes_lookup ON batch_certificate_proof_nodes (batch_certificate_id, proof_index ASC);
CREATE INDEX idx_blockchain_tx_batch_status ON blockchain_transactions (batch_id, status, prepared_at DESC);

COMMIT;
