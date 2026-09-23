-- ============================================================================
-- Anchoring Domain sqlc Queries (Phase 5B)
-- ============================================================================

-- ============================================================================
-- 1. MERKLE BATCH QUERIES
-- ============================================================================

-- name: CreateMerkleBatch :one
INSERT INTO merkle_batches (
    canonical_batch_id, tree_algorithm, tree_version,
    leaf_encoding_version, proof_format_version, status
) VALUES (
    sqlc.arg('canonical_batch_id'), sqlc.arg('tree_algorithm'), sqlc.arg('tree_version'),
    sqlc.arg('leaf_encoding_version'), sqlc.arg('proof_format_version'), 'BUILDING'
)
RETURNING *;

-- name: GetMerkleBatchByID :one
SELECT * FROM merkle_batches
WHERE id = sqlc.arg('id');

-- name: GetMerkleBatchByCanonicalID :one
SELECT * FROM merkle_batches
WHERE canonical_batch_id = sqlc.arg('canonical_batch_id');

-- name: GetMerkleBatchByNumber :one
SELECT * FROM merkle_batches
WHERE batch_number = sqlc.arg('batch_number');

-- name: ListMerkleBatches :many
SELECT * FROM merkle_batches
ORDER BY created_at DESC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: CountMerkleBatches :one
SELECT COUNT(*) FROM merkle_batches;

-- name: FinalizeBatchTree :one
UPDATE merkle_batches
SET
    merkle_root = sqlc.arg('merkle_root'),
    leaf_count = sqlc.arg('leaf_count'),
    status = 'READY',
    ready_at = NOW(),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND status = 'BUILDING'
RETURNING *;

-- name: ClaimNextReadyBatch :one
UPDATE merkle_batches
SET
    status = 'SUBMITTING',
    claimed_by = sqlc.arg('claimed_by'),
    claim_expires_at = NOW() + (sqlc.arg('lease_seconds')::INT * INTERVAL '1 second'),
    chain_id = sqlc.arg('chain_id'),
    contract_address = sqlc.arg('contract_address'),
    updated_at = NOW()
WHERE id = (
    SELECT id FROM merkle_batches
    WHERE (status = 'READY' OR (status = 'SUBMITTING' AND claim_expires_at < NOW()))
    ORDER BY created_at ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING *;

-- name: SetAuthoritativeTransaction :one
UPDATE merkle_batches
SET
    authoritative_transaction_id = sqlc.arg('authoritative_transaction_id'),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: MarkBatchSubmitted :one
UPDATE merkle_batches
SET
    status = 'SUBMITTED',
    claimed_by = NULL,
    claim_expires_at = NULL,
    submitted_at = NOW(),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND status = 'SUBMITTING'
RETURNING *;

-- name: MarkBatchConfirmed :one
UPDATE merkle_batches
SET
    status = 'CONFIRMED',
    block_number = sqlc.arg('block_number'),
    block_hash = sqlc.arg('block_hash'),
    confirmation_count = sqlc.arg('confirmation_count'),
    confirmed_at = NOW(),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND status = 'SUBMITTED'
RETURNING *;

-- name: MarkBatchFailed :one
UPDATE merkle_batches
SET
    status = 'FAILED',
    failure_stage = sqlc.arg('failure_stage'),
    failure_code = sqlc.arg('failure_code'),
    failure_detail_code = sqlc.arg('failure_detail_code'),
    claimed_by = NULL,
    claim_expires_at = NULL,
    failed_at = NOW(),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: ExtendBatchClaim :one
UPDATE merkle_batches
SET
    claim_expires_at = NOW() + (sqlc.arg('lease_seconds')::INT * INTERVAL '1 second'),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND status = 'SUBMITTING'
  AND claimed_by = sqlc.arg('claimed_by')
RETURNING *;

-- name: ResetExpiredBatchClaim :one
UPDATE merkle_batches
SET
    status = 'READY',
    claimed_by = NULL,
    claim_expires_at = NULL,
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND status = 'SUBMITTING'
  AND claim_expires_at < NOW()
RETURNING *;

-- ============================================================================
-- 2. BATCH CERTIFICATES QUERIES
-- ============================================================================

-- name: FindEligibleCertificatesForBatch :many
SELECT c.id, c.public_id, c.document_hash, c.status
FROM certificates c
LEFT JOIN batch_certificates bc ON bc.certificate_id = c.id
WHERE bc.id IS NULL
  AND c.status IN ('ISSUED', 'REVOKED', 'REPLACED')
  AND c.document_hash IS NOT NULL
ORDER BY c.created_at ASC
LIMIT sqlc.arg('limit');

-- name: CreateBatchCertificate :one
INSERT INTO batch_certificates (
    batch_id, certificate_id, leaf_index, leaf_hash, proof_depth, public_id, document_hash
) VALUES (
    sqlc.arg('batch_id'), sqlc.arg('certificate_id'), sqlc.arg('leaf_index'),
    sqlc.arg('leaf_hash'), sqlc.arg('proof_depth'), sqlc.arg('public_id'),
    sqlc.arg('document_hash')
)
RETURNING *;

-- name: GetBatchCertificateByID :one
SELECT * FROM batch_certificates
WHERE id = sqlc.arg('id');

-- name: GetBatchCertificateByCertID :one
SELECT * FROM batch_certificates
WHERE certificate_id = sqlc.arg('certificate_id');

-- name: GetBatchCertificateByPublicID :one
SELECT * FROM batch_certificates
WHERE public_id = sqlc.arg('public_id');

-- name: ListBatchCertificatesByBatchID :many
SELECT * FROM batch_certificates
WHERE batch_id = sqlc.arg('batch_id')
ORDER BY leaf_index ASC;

-- ============================================================================
-- 3. PROOF NODES QUERIES
-- ============================================================================

-- name: CreateBatchCertificateProofNode :one
INSERT INTO batch_certificate_proof_nodes (
    batch_certificate_id, proof_index, sibling_hash
) VALUES (
    sqlc.arg('batch_certificate_id'), sqlc.arg('proof_index'), sqlc.arg('sibling_hash')
)
RETURNING *;

-- name: GetProofNodesByBatchCertID :many
SELECT proof_index, sibling_hash
FROM batch_certificate_proof_nodes
WHERE batch_certificate_id = sqlc.arg('batch_certificate_id')
ORDER BY proof_index ASC;

-- ============================================================================
-- 4. SIGNER NONCE RESERVATION QUERIES
-- ============================================================================

-- name: ReserveSignerNonce :one
INSERT INTO signer_nonce_reservations (
    batch_id, chain_id, signer_address, nonce, status
) VALUES (
    sqlc.arg('batch_id'), sqlc.arg('chain_id'), sqlc.arg('signer_address'),
    sqlc.arg('nonce'), 'ACTIVE'
)
RETURNING *;

-- name: GetHighestNonceBySigner :one
SELECT COALESCE(MAX(nonce), -1)::BIGINT AS max_nonce
FROM signer_nonce_reservations
WHERE chain_id = sqlc.arg('chain_id')
  AND signer_address = sqlc.arg('signer_address');

-- name: GetNonceReservationByID :one
SELECT * FROM signer_nonce_reservations
WHERE id = sqlc.arg('id');

-- name: GetActiveNonceReservationByBatchID :one
SELECT * FROM signer_nonce_reservations
WHERE batch_id = sqlc.arg('batch_id')
  AND status = 'ACTIVE'
LIMIT 1;

-- name: CommitNonceReservation :one
UPDATE signer_nonce_reservations
SET
    status = 'COMMITTED',
    committed_at = NOW()
WHERE id = sqlc.arg('id')
  AND status = 'ACTIVE'
RETURNING *;

-- name: ReleaseNonceReservation :one
UPDATE signer_nonce_reservations
SET
    status = 'RELEASED'
WHERE id = sqlc.arg('id')
  AND status = 'ACTIVE'
RETURNING *;

-- ============================================================================
-- 5. BLOCKCHAIN TRANSACTION ATTEMPT QUERIES
-- ============================================================================

-- name: CreateBlockchainTransaction :one
INSERT INTO blockchain_transactions (
    batch_id, nonce_reservation_id, replacement_sequence, chain_id,
    from_address, to_address, nonce, transaction_type, value_wei,
    calldata, gas_limit, max_fee_per_gas_wei, max_priority_fee_per_gas_wei,
    tx_hash, status, replaces_transaction_id, prepared_at
) VALUES (
    sqlc.arg('batch_id'), sqlc.arg('nonce_reservation_id'), sqlc.arg('replacement_sequence'),
    sqlc.arg('chain_id'), sqlc.arg('from_address'), sqlc.arg('to_address'),
    sqlc.arg('nonce'), sqlc.arg('transaction_type'), sqlc.arg('value_wei'),
    sqlc.arg('calldata'), sqlc.arg('gas_limit'), sqlc.arg('max_fee_per_gas_wei'),
    sqlc.arg('max_priority_fee_per_gas_wei'), sqlc.arg('tx_hash'), 'PREPARED',
    sqlc.narg('replaces_transaction_id'), NOW()
)
RETURNING *;

-- name: GetBlockchainTransactionByID :one
SELECT * FROM blockchain_transactions
WHERE id = sqlc.arg('id');

-- name: GetBlockchainTransactionByHash :one
SELECT * FROM blockchain_transactions
WHERE tx_hash = sqlc.arg('tx_hash');

-- name: GetActiveTransactionByReservationID :one
SELECT * FROM blockchain_transactions
WHERE nonce_reservation_id = sqlc.arg('nonce_reservation_id')
  AND status IN ('PREPARED', 'BROADCAST')
LIMIT 1;

-- name: GetAuthoritativeTransactionForBatch :one
SELECT bt.*
FROM blockchain_transactions bt
JOIN merkle_batches mb ON mb.authoritative_transaction_id = bt.id
WHERE mb.id = sqlc.arg('batch_id');

-- name: ListTransactionsByBatchID :many
SELECT * FROM blockchain_transactions
WHERE batch_id = sqlc.arg('batch_id')
ORDER BY replacement_sequence ASC;

-- name: MarkTransactionBroadcast :one
UPDATE blockchain_transactions
SET
    status = 'BROADCAST',
    broadcast_at = NOW()
WHERE id = sqlc.arg('id')
  AND status = 'PREPARED'
RETURNING *;

-- name: MarkTransactionMined :one
UPDATE blockchain_transactions
SET
    status = 'MINED',
    block_number = sqlc.arg('block_number'),
    block_hash = sqlc.arg('block_hash'),
    gas_used = sqlc.arg('gas_used'),
    mined_at = NOW()
WHERE id = sqlc.arg('id')
  AND status = 'BROADCAST'
RETURNING *;

-- name: MarkTransactionReplaced :one
UPDATE blockchain_transactions
SET
    status = 'REPLACED',
    replaced_at = NOW()
WHERE id = sqlc.arg('id')
  AND status IN ('PREPARED', 'BROADCAST')
RETURNING *;

-- name: MarkTransactionFailed :one
UPDATE blockchain_transactions
SET
    status = 'FAILED',
    failure_code = sqlc.arg('failure_code'),
    failure_detail_code = sqlc.arg('failure_detail_code'),
    failed_at = NOW()
WHERE id = sqlc.arg('id')
  AND status IN ('PREPARED', 'BROADCAST')
RETURNING *;
