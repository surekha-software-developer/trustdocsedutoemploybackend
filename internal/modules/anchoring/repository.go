package anchoring

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
)

// EligibleCertificate represents an ISSUED certificate eligible for inclusion in a Merkle batch.
type EligibleCertificate struct {
	ID           pgtype.UUID
	PublicID     string
	DocumentHash pgtype.Text
	Status       string
}

// LeafData holds leaf computation output ready for database persistence.
type LeafData struct {
	CertificateID pgtype.UUID
	PublicID      string
	DocumentHash  string
	LeafIndex     int32
	LeafHash      string
	ProofDepth    int32
	ProofNodes    []string
}

// CertificateRow represents minimal certificate verification details.
type CertificateRow struct {
	ID           pgtype.UUID
	PublicID     string
	Status       string
	DocumentHash pgtype.Text
}

// Repository defines all database operations required by the anchoring domain.
type Repository interface {
	FindEligibleCertificates(ctx context.Context, limit int32) ([]EligibleCertificate, error)
	CreateBatchWithCertificates(
		ctx context.Context,
		canonicalBatchID string,
		treeAlgo string,
		treeVer int32,
		leafVer string,
		proofVer string,
		leaves []LeafData,
		root string,
	) (*db.MerkleBatch, error)
	GetBatchByID(ctx context.Context, id pgtype.UUID) (*db.MerkleBatch, error)
	GetBatchByCanonicalID(ctx context.Context, canonicalID string) (*db.MerkleBatch, error)
	GetBatchByNumber(ctx context.Context, batchNumber int64) (*db.MerkleBatch, error)
	ListBatches(ctx context.Context, limit int32, offset int32) ([]db.MerkleBatch, error)
	CountBatches(ctx context.Context) (int64, error)
	ClaimNextReadyBatch(ctx context.Context, claimedBy string, leaseSeconds int32, chainID int64, contractAddress string) (*db.MerkleBatch, error)
	ExtendBatchClaim(ctx context.Context, batchID pgtype.UUID, claimedBy string, leaseSeconds int32) error
	ResetExpiredBatchClaim(ctx context.Context, batchID pgtype.UUID) error
	MarkBatchSubmitted(ctx context.Context, batchID pgtype.UUID) error
	MarkBatchConfirmed(ctx context.Context, batchID pgtype.UUID, blockNumber int64, blockHash string, confirmationCount int32) error
	MarkBatchFailed(ctx context.Context, batchID pgtype.UUID, failureStage string, failureCode string, failureDetailCode string) error
	SetAuthoritativeTransaction(ctx context.Context, batchID pgtype.UUID, txID pgtype.UUID) error

	ReserveSignerNonce(ctx context.Context, batchID pgtype.UUID, chainID int64, signerAddress string, nonce int64) (*db.SignerNonceReservation, error)
	GetHighestNonceBySigner(ctx context.Context, chainID int64, signerAddress string) (int64, error)
	GetActiveNonceReservation(ctx context.Context, batchID pgtype.UUID) (*db.SignerNonceReservation, error)
	CommitNonceReservation(ctx context.Context, reservationID pgtype.UUID) error
	ReleaseNonceReservation(ctx context.Context, reservationID pgtype.UUID) error

	CreateBlockchainTransaction(ctx context.Context, arg db.CreateBlockchainTransactionParams) (*db.BlockchainTransaction, error)
	GetActiveTransactionByReservationID(ctx context.Context, reservationID pgtype.UUID) (*db.BlockchainTransaction, error)
	GetAuthoritativeTransactionForBatch(ctx context.Context, batchID pgtype.UUID) (*db.BlockchainTransaction, error)
	ListTransactionsByBatchID(ctx context.Context, batchID pgtype.UUID) ([]db.BlockchainTransaction, error)
	MarkTransactionBroadcast(ctx context.Context, txID pgtype.UUID) error
	MarkTransactionMined(ctx context.Context, txID pgtype.UUID, blockNumber int64, blockHash string, gasUsed int64) error
	MarkTransactionReplaced(ctx context.Context, txID pgtype.UUID) error
	MarkTransactionFailed(ctx context.Context, txID pgtype.UUID, failureCode string, failureDetailCode string) error

	GetBatchCertificateByPublicID(ctx context.Context, publicID string) (*db.BatchCertificate, error)
	GetProofNodesByBatchCertID(ctx context.Context, batchCertID pgtype.UUID) ([]db.GetProofNodesByBatchCertIDRow, error)
	GetCertificateByPublicID(ctx context.Context, publicID string) (*CertificateRow, error)
}

// PgxRepository implements Repository using pgxpool and sqlc.
type PgxRepository struct {
	pool    *pgxpool.Pool
	queries *db.Queries
}

// NewPgxRepository constructs a new PgxRepository.
func NewPgxRepository(pool *pgxpool.Pool) *PgxRepository {
	return &PgxRepository{
		pool:    pool,
		queries: db.New(pool),
	}
}

func (r *PgxRepository) FindEligibleCertificates(ctx context.Context, limit int32) ([]EligibleCertificate, error) {
	rows, err := r.queries.FindEligibleCertificatesForBatch(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query eligible certificates: %w", err)
	}

	result := make([]EligibleCertificate, len(rows))
	for i, row := range rows {
		result[i] = EligibleCertificate{
			ID:           row.ID,
			PublicID:     row.PublicID,
			DocumentHash: row.DocumentHash,
			Status:       row.Status,
		}
	}
	return result, nil
}

func (r *PgxRepository) CreateBatchWithCertificates(
	ctx context.Context,
	canonicalBatchID string,
	treeAlgo string,
	treeVer int32,
	leafVer string,
	proofVer string,
	leaves []LeafData,
	root string,
) (*db.MerkleBatch, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	q := r.queries.WithTx(tx)

	// 1. Create batch in BUILDING status
	batch, err := q.CreateMerkleBatch(ctx, db.CreateMerkleBatchParams{
		CanonicalBatchID:    canonicalBatchID,
		TreeAlgorithm:       treeAlgo,
		TreeVersion:         treeVer,
		LeafEncodingVersion: leafVer,
		ProofFormatVersion:  proofVer,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to insert merkle batch: %w", err)
	}

	// 2. Insert immutable snapshots and proof nodes
	for _, leaf := range leaves {
		batchCert, err := q.CreateBatchCertificate(ctx, db.CreateBatchCertificateParams{
			BatchID:       batch.ID,
			CertificateID: leaf.CertificateID,
			LeafIndex:     leaf.LeafIndex,
			LeafHash:      leaf.LeafHash,
			ProofDepth:    leaf.ProofDepth,
			PublicID:      leaf.PublicID,
			DocumentHash:  leaf.DocumentHash,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to insert batch certificate: %w", err)
		}

		for pIdx, sibHash := range leaf.ProofNodes {
			_, err = q.CreateBatchCertificateProofNode(ctx, db.CreateBatchCertificateProofNodeParams{
				BatchCertificateID: batchCert.ID,
				ProofIndex:         int32(pIdx),
				SiblingHash:        sibHash,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to insert proof node: %w", err)
			}
		}
	}

	// 3. Atomically finalize BUILDING -> READY
	finalizedBatch, err := q.FinalizeBatchTree(ctx, db.FinalizeBatchTreeParams{
		ID:         batch.ID,
		MerkleRoot: pgtype.Text{String: root, Valid: true},
		LeafCount:  int32(len(leaves)),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to finalize batch tree: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	return &finalizedBatch, nil
}

func (r *PgxRepository) GetBatchByID(ctx context.Context, id pgtype.UUID) (*db.MerkleBatch, error) {
	batch, err := r.queries.GetMerkleBatchByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return &batch, nil
}

func (r *PgxRepository) GetBatchByCanonicalID(ctx context.Context, canonicalID string) (*db.MerkleBatch, error) {
	batch, err := r.queries.GetMerkleBatchByCanonicalID(ctx, canonicalID)
	if err != nil {
		return nil, err
	}
	return &batch, nil
}

func (r *PgxRepository) GetBatchByNumber(ctx context.Context, batchNumber int64) (*db.MerkleBatch, error) {
	batch, err := r.queries.GetMerkleBatchByNumber(ctx, batchNumber)
	if err != nil {
		return nil, err
	}
	return &batch, nil
}

func (r *PgxRepository) ListBatches(ctx context.Context, limit int32, offset int32) ([]db.MerkleBatch, error) {
	return r.queries.ListMerkleBatches(ctx, db.ListMerkleBatchesParams{
		Limit:  limit,
		Offset: offset,
	})
}

func (r *PgxRepository) CountBatches(ctx context.Context) (int64, error) {
	return r.queries.CountMerkleBatches(ctx)
}

func (r *PgxRepository) ClaimNextReadyBatch(ctx context.Context, claimedBy string, leaseSeconds int32, chainID int64, contractAddress string) (*db.MerkleBatch, error) {
	batch, err := r.queries.ClaimNextReadyBatch(ctx, db.ClaimNextReadyBatchParams{
		ClaimedBy:       pgtype.Text{String: claimedBy, Valid: true},
		LeaseSeconds:    leaseSeconds,
		ChainID:         pgtype.Int8{Int64: chainID, Valid: true},
		ContractAddress: pgtype.Text{String: contractAddress, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	return &batch, nil
}

func (r *PgxRepository) ExtendBatchClaim(ctx context.Context, batchID pgtype.UUID, claimedBy string, leaseSeconds int32) error {
	_, err := r.queries.ExtendBatchClaim(ctx, db.ExtendBatchClaimParams{
		ID:           batchID,
		ClaimedBy:    pgtype.Text{String: claimedBy, Valid: true},
		LeaseSeconds: leaseSeconds,
	})
	return err
}

func (r *PgxRepository) ResetExpiredBatchClaim(ctx context.Context, batchID pgtype.UUID) error {
	_, err := r.queries.ResetExpiredBatchClaim(ctx, batchID)
	return err
}

func (r *PgxRepository) MarkBatchSubmitted(ctx context.Context, batchID pgtype.UUID) error {
	_, err := r.queries.MarkBatchSubmitted(ctx, batchID)
	return err
}

func (r *PgxRepository) MarkBatchConfirmed(ctx context.Context, batchID pgtype.UUID, blockNumber int64, blockHash string, confirmationCount int32) error {
	_, err := r.queries.MarkBatchConfirmed(ctx, db.MarkBatchConfirmedParams{
		ID:                batchID,
		BlockNumber:       pgtype.Int8{Int64: blockNumber, Valid: true},
		BlockHash:         pgtype.Text{String: blockHash, Valid: true},
		ConfirmationCount: confirmationCount,
	})
	return err
}

func (r *PgxRepository) MarkBatchFailed(ctx context.Context, batchID pgtype.UUID, failureStage string, failureCode string, failureDetailCode string) error {
	_, err := r.queries.MarkBatchFailed(ctx, db.MarkBatchFailedParams{
		ID:                batchID,
		FailureStage:      pgtype.Text{String: failureStage, Valid: true},
		FailureCode:       pgtype.Text{String: failureCode, Valid: true},
		FailureDetailCode: pgtype.Text{String: failureDetailCode, Valid: true},
	})
	return err
}

func (r *PgxRepository) SetAuthoritativeTransaction(ctx context.Context, batchID pgtype.UUID, txID pgtype.UUID) error {
	_, err := r.queries.SetAuthoritativeTransaction(ctx, db.SetAuthoritativeTransactionParams{
		ID:                         batchID,
		AuthoritativeTransactionID: txID,
	})
	return err
}

func (r *PgxRepository) ReserveSignerNonce(ctx context.Context, batchID pgtype.UUID, chainID int64, signerAddress string, nonce int64) (*db.SignerNonceReservation, error) {
	res, err := r.queries.ReserveSignerNonce(ctx, db.ReserveSignerNonceParams{
		BatchID:       batchID,
		ChainID:       chainID,
		SignerAddress: signerAddress,
		Nonce:         nonce,
	})
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (r *PgxRepository) GetHighestNonceBySigner(ctx context.Context, chainID int64, signerAddress string) (int64, error) {
	maxNonce, err := r.queries.GetHighestNonceBySigner(ctx, db.GetHighestNonceBySignerParams{
		ChainID:       chainID,
		SignerAddress: signerAddress,
	})
	if err != nil {
		return -1, err
	}
	return maxNonce, nil
}

func (r *PgxRepository) GetActiveNonceReservation(ctx context.Context, batchID pgtype.UUID) (*db.SignerNonceReservation, error) {
	res, err := r.queries.GetActiveNonceReservationByBatchID(ctx, batchID)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (r *PgxRepository) CommitNonceReservation(ctx context.Context, reservationID pgtype.UUID) error {
	_, err := r.queries.CommitNonceReservation(ctx, reservationID)
	return err
}

func (r *PgxRepository) ReleaseNonceReservation(ctx context.Context, reservationID pgtype.UUID) error {
	_, err := r.queries.ReleaseNonceReservation(ctx, reservationID)
	return err
}

func (r *PgxRepository) CreateBlockchainTransaction(ctx context.Context, arg db.CreateBlockchainTransactionParams) (*db.BlockchainTransaction, error) {
	tx, err := r.queries.CreateBlockchainTransaction(ctx, arg)
	if err != nil {
		return nil, err
	}
	return &tx, nil
}

func (r *PgxRepository) GetActiveTransactionByReservationID(ctx context.Context, reservationID pgtype.UUID) (*db.BlockchainTransaction, error) {
	tx, err := r.queries.GetActiveTransactionByReservationID(ctx, reservationID)
	if err != nil {
		return nil, err
	}
	return &tx, nil
}

func (r *PgxRepository) GetAuthoritativeTransactionForBatch(ctx context.Context, batchID pgtype.UUID) (*db.BlockchainTransaction, error) {
	tx, err := r.queries.GetAuthoritativeTransactionForBatch(ctx, batchID)
	if err != nil {
		return nil, err
	}
	return &tx, nil
}

func (r *PgxRepository) ListTransactionsByBatchID(ctx context.Context, batchID pgtype.UUID) ([]db.BlockchainTransaction, error) {
	return r.queries.ListTransactionsByBatchID(ctx, batchID)
}

func (r *PgxRepository) MarkTransactionBroadcast(ctx context.Context, txID pgtype.UUID) error {
	_, err := r.queries.MarkTransactionBroadcast(ctx, txID)
	return err
}

func (r *PgxRepository) MarkTransactionMined(ctx context.Context, txID pgtype.UUID, blockNumber int64, blockHash string, gasUsed int64) error {
	_, err := r.queries.MarkTransactionMined(ctx, db.MarkTransactionMinedParams{
		ID:          txID,
		BlockNumber: pgtype.Int8{Int64: blockNumber, Valid: true},
		BlockHash:   pgtype.Text{String: blockHash, Valid: true},
		GasUsed:     pgtype.Int8{Int64: gasUsed, Valid: true},
	})
	return err
}

func (r *PgxRepository) MarkTransactionReplaced(ctx context.Context, txID pgtype.UUID) error {
	_, err := r.queries.MarkTransactionReplaced(ctx, txID)
	return err
}

func (r *PgxRepository) MarkTransactionFailed(ctx context.Context, txID pgtype.UUID, failureCode string, failureDetailCode string) error {
	_, err := r.queries.MarkTransactionFailed(ctx, db.MarkTransactionFailedParams{
		ID:                txID,
		FailureCode:       pgtype.Text{String: failureCode, Valid: true},
		FailureDetailCode: pgtype.Text{String: failureDetailCode, Valid: true},
	})
	return err
}

func (r *PgxRepository) GetBatchCertificateByPublicID(ctx context.Context, publicID string) (*db.BatchCertificate, error) {
	bc, err := r.queries.GetBatchCertificateByPublicID(ctx, publicID)
	if err != nil {
		return nil, err
	}
	return &bc, nil
}

func (r *PgxRepository) GetProofNodesByBatchCertID(ctx context.Context, batchCertID pgtype.UUID) ([]db.GetProofNodesByBatchCertIDRow, error) {
	return r.queries.GetProofNodesByBatchCertID(ctx, batchCertID)
}

func (r *PgxRepository) GetCertificateByPublicID(ctx context.Context, publicID string) (*CertificateRow, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, public_id, status, document_hash
		FROM certificates
		WHERE public_id = $1
		LIMIT 1;
	`, publicID)

	var cert CertificateRow
	if err := row.Scan(&cert.ID, &cert.PublicID, &cert.Status, &cert.DocumentHash); err != nil {
		return nil, err
	}
	return &cert, nil
}

// UUIDToString converts pgtype.UUID to lowercase hyphenated string.
func UUIDToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	src := u.Bytes
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		src[0:4], src[4:6], src[6:8], src[8:10], src[10:16])
}

// StringToUUID converts string to pgtype.UUID.
func StringToUUID(s string) pgtype.UUID {
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	bytes, err := hex.DecodeString(clean)
	if err != nil || len(bytes) != 16 {
		return pgtype.UUID{Valid: false}
	}
	var out pgtype.UUID
	copy(out.Bytes[:], bytes)
	out.Valid = true
	return out
}
