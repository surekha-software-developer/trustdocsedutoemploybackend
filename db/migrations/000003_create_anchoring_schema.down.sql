BEGIN;

-- ============================================================================
-- 1. DROP CIRCULAR FOREIGN KEY FIRST
-- ============================================================================
-- fk_merkle_batches_authoritative_tx links merkle_batches back to blockchain_transactions.
-- It must be explicitly dropped before either table can be dropped without FK violations.
ALTER TABLE IF EXISTS merkle_batches
    DROP CONSTRAINT IF EXISTS fk_merkle_batches_authoritative_tx;

-- ============================================================================
-- 2. DROP TABLES IN STRICT REVERSE DEPENDENCY ORDER
-- ============================================================================
-- 1. batch_certificate_proof_nodes references batch_certificates
DROP TABLE IF EXISTS batch_certificate_proof_nodes;

-- 2. batch_certificates references merkle_batches and certificates
DROP TABLE IF EXISTS batch_certificates;

-- 3. blockchain_transactions references signer_nonce_reservations, merkle_batches, and itself
DROP TABLE IF EXISTS blockchain_transactions;

-- 4. signer_nonce_reservations references merkle_batches
DROP TABLE IF EXISTS signer_nonce_reservations;

-- 5. merkle_batches has no more inbound foreign keys
DROP TABLE IF EXISTS merkle_batches;

COMMIT;
