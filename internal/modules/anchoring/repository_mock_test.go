package anchoring

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
)

// MockRepository provides an in-memory thread-safe implementation of Repository for unit tests.
type MockRepository struct {
	mu sync.RWMutex

	batches         map[string]*db.MerkleBatch
	batchCerts      map[string]*db.BatchCertificate // key: publicID
	batchCertsByID  map[string]*db.BatchCertificate // key: UUID
	proofNodes      map[string][]db.GetProofNodesByBatchCertIDRow
	reservations    map[string]*db.SignerNonceReservation
	transactions    map[string]*db.BlockchainTransaction
	certificates    map[string]*CertificateRow
	eligibleCerts   []EligibleCertificate
	highestBatchNum int64

	// Error injection triggers
	FindEligibleErr      error
	CreateBatchErr       error
	ClaimBatchErr        error
	ReserveNonceErr      error
	CreateTxErr          error
	MarkConfirmedErr     error
	MarkFailedErr        error
	GetCertByPublicIDErr error
}

// NewMockRepository constructs an empty MockRepository.
func NewMockRepository() *MockRepository {
	return &MockRepository{
		batches:        make(map[string]*db.MerkleBatch),
		batchCerts:     make(map[string]*db.BatchCertificate),
		batchCertsByID: make(map[string]*db.BatchCertificate),
		proofNodes:     make(map[string][]db.GetProofNodesByBatchCertIDRow),
		reservations:   make(map[string]*db.SignerNonceReservation),
		transactions:   make(map[string]*db.BlockchainTransaction),
		certificates:   make(map[string]*CertificateRow),
	}
}

func (m *MockRepository) AddEligibleCertificate(cert EligibleCertificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eligibleCerts = append(m.eligibleCerts, cert)
	m.certificates[cert.PublicID] = &CertificateRow{
		ID:           cert.ID,
		PublicID:     cert.PublicID,
		Status:       cert.Status,
		DocumentHash: cert.DocumentHash,
	}
}

func (m *MockRepository) FindEligibleCertificates(ctx context.Context, limit int32) ([]EligibleCertificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FindEligibleErr != nil {
		return nil, m.FindEligibleErr
	}

	result := make([]EligibleCertificate, 0)
	for _, c := range m.eligibleCerts {
		if _, exists := m.batchCerts[c.PublicID]; !exists {
			result = append(result, c)
			if int32(len(result)) >= limit {
				break
			}
		}
	}
	return result, nil
}

func (m *MockRepository) CreateBatchWithCertificates(
	ctx context.Context,
	canonicalBatchID string,
	treeAlgo string,
	treeVer int32,
	leafVer string,
	proofVer string,
	leaves []LeafData,
	root string,
) (*db.MerkleBatch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CreateBatchErr != nil {
		return nil, m.CreateBatchErr
	}

	m.highestBatchNum++
	batchID := randomUUID()
	now := time.Now().UTC()

	batch := &db.MerkleBatch{
		ID:                  batchID,
		BatchNumber:         m.highestBatchNum,
		CanonicalBatchID:    canonicalBatchID,
		Status:              "READY",
		TreeAlgorithm:       treeAlgo,
		TreeVersion:         treeVer,
		LeafEncodingVersion: leafVer,
		ProofFormatVersion:  proofVer,
		MerkleRoot:          pgtype.Text{String: root, Valid: true},
		LeafCount:           int32(len(leaves)),
		CreatedAt:           pgtype.Timestamptz{Time: now, Valid: true},
		UpdatedAt:           pgtype.Timestamptz{Time: now, Valid: true},
		ReadyAt:             pgtype.Timestamptz{Time: now, Valid: true},
	}
	m.batches[UUIDToString(batchID)] = batch

	for _, leaf := range leaves {
		bcID := randomUUID()
		bc := &db.BatchCertificate{
			ID:            bcID,
			BatchID:       batchID,
			CertificateID: leaf.CertificateID,
			LeafIndex:     leaf.LeafIndex,
			LeafHash:      leaf.LeafHash,
			ProofDepth:    leaf.ProofDepth,
			PublicID:      leaf.PublicID,
			DocumentHash:  leaf.DocumentHash,
			CreatedAt:     pgtype.Timestamptz{Time: now, Valid: true},
		}
		m.batchCerts[leaf.PublicID] = bc
		m.batchCertsByID[UUIDToString(bcID)] = bc

		pNodes := make([]db.GetProofNodesByBatchCertIDRow, len(leaf.ProofNodes))
		for pIdx, sHash := range leaf.ProofNodes {
			pNodes[pIdx] = db.GetProofNodesByBatchCertIDRow{
				ProofIndex:  int32(pIdx),
				SiblingHash: sHash,
			}
		}
		m.proofNodes[UUIDToString(bcID)] = pNodes
	}

	return batch, nil
}

func (m *MockRepository) GetBatchByID(ctx context.Context, id pgtype.UUID) (*db.MerkleBatch, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.batches[UUIDToString(id)]
	if !ok {
		return nil, fmt.Errorf("batch not found")
	}
	return b, nil
}

func (m *MockRepository) GetBatchByCanonicalID(ctx context.Context, canonicalID string) (*db.MerkleBatch, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.batches {
		if b.CanonicalBatchID == canonicalID {
			return b, nil
		}
	}
	return nil, fmt.Errorf("batch not found")
}

func (m *MockRepository) GetBatchByNumber(ctx context.Context, batchNumber int64) (*db.MerkleBatch, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.batches {
		if b.BatchNumber == batchNumber {
			return b, nil
		}
	}
	return nil, fmt.Errorf("batch not found")
}

func (m *MockRepository) ListBatches(ctx context.Context, limit int32, offset int32) ([]db.MerkleBatch, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]db.MerkleBatch, 0, len(m.batches))
	for _, b := range m.batches {
		list = append(list, *b)
	}
	return list, nil
}

func (m *MockRepository) CountBatches(ctx context.Context) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return int64(len(m.batches)), nil
}

func (m *MockRepository) ClaimNextReadyBatch(ctx context.Context, claimedBy string, leaseSeconds int32, chainID int64, contractAddress string) (*db.MerkleBatch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ClaimBatchErr != nil {
		return nil, m.ClaimBatchErr
	}

	now := time.Now().UTC()
	for _, b := range m.batches {
		isReady := b.Status == "READY"
		isExpired := b.Status == "SUBMITTING" && b.ClaimExpiresAt.Valid && b.ClaimExpiresAt.Time.Before(now)
		if isReady || isExpired {
			b.Status = "SUBMITTING"
			b.ClaimedBy = pgtype.Text{String: claimedBy, Valid: true}
			b.ClaimExpiresAt = pgtype.Timestamptz{Time: now.Add(time.Duration(leaseSeconds) * time.Second), Valid: true}
			b.ChainID = pgtype.Int8{Int64: chainID, Valid: true}
			b.ContractAddress = pgtype.Text{String: contractAddress, Valid: true}
			b.UpdatedAt = pgtype.Timestamptz{Time: now, Valid: true}
			return b, nil
		}
	}
	return nil, fmt.Errorf("no ready batch available")
}

func (m *MockRepository) ExtendBatchClaim(ctx context.Context, batchID pgtype.UUID, claimedBy string, leaseSeconds int32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.batches[UUIDToString(batchID)]
	if !ok {
		return fmt.Errorf("batch not found")
	}
	if b.Status != "SUBMITTING" || b.ClaimedBy.String != claimedBy {
		return fmt.Errorf("cannot extend claim: lease not held")
	}
	b.ClaimExpiresAt = pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Duration(leaseSeconds) * time.Second), Valid: true}
	return nil
}

func (m *MockRepository) ResetExpiredBatchClaim(ctx context.Context, batchID pgtype.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.batches[UUIDToString(batchID)]
	if !ok {
		return fmt.Errorf("batch not found")
	}
	b.Status = "READY"
	b.ClaimedBy = pgtype.Text{Valid: false}
	b.ClaimExpiresAt = pgtype.Timestamptz{Valid: false}
	return nil
}

func (m *MockRepository) MarkBatchSubmitted(ctx context.Context, batchID pgtype.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.batches[UUIDToString(batchID)]
	if !ok {
		return fmt.Errorf("batch not found")
	}
	b.Status = "SUBMITTED"
	b.ClaimedBy = pgtype.Text{Valid: false}
	b.ClaimExpiresAt = pgtype.Timestamptz{Valid: false}
	b.SubmittedAt = pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	return nil
}

func (m *MockRepository) MarkBatchConfirmed(ctx context.Context, batchID pgtype.UUID, blockNumber int64, blockHash string, confirmationCount int32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.MarkConfirmedErr != nil {
		return m.MarkConfirmedErr
	}
	b, ok := m.batches[UUIDToString(batchID)]
	if !ok {
		return fmt.Errorf("batch not found")
	}
	b.Status = "CONFIRMED"
	b.BlockNumber = pgtype.Int8{Int64: blockNumber, Valid: true}
	b.BlockHash = pgtype.Text{String: blockHash, Valid: true}
	b.ConfirmationCount = confirmationCount
	b.ConfirmedAt = pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	return nil
}

func (m *MockRepository) MarkBatchFailed(ctx context.Context, batchID pgtype.UUID, failureStage string, failureCode string, failureDetailCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.MarkFailedErr != nil {
		return m.MarkFailedErr
	}
	b, ok := m.batches[UUIDToString(batchID)]
	if !ok {
		return fmt.Errorf("batch not found")
	}
	b.Status = "FAILED"
	b.FailureStage = pgtype.Text{String: failureStage, Valid: true}
	b.FailureCode = pgtype.Text{String: failureCode, Valid: true}
	b.FailureDetailCode = pgtype.Text{String: failureDetailCode, Valid: true}
	b.ClaimedBy = pgtype.Text{Valid: false}
	b.ClaimExpiresAt = pgtype.Timestamptz{Valid: false}
	b.FailedAt = pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	return nil
}

func (m *MockRepository) SetAuthoritativeTransaction(ctx context.Context, batchID pgtype.UUID, txID pgtype.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.batches[UUIDToString(batchID)]
	if !ok {
		return fmt.Errorf("batch not found")
	}
	b.AuthoritativeTransactionID = txID
	return nil
}

func (m *MockRepository) ReserveSignerNonce(ctx context.Context, batchID pgtype.UUID, chainID int64, signerAddress string, nonce int64) (*db.SignerNonceReservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReserveNonceErr != nil {
		return nil, m.ReserveNonceErr
	}

	// Enforce UNIQUE(chain_id, signer_address, nonce)
	for _, res := range m.reservations {
		if res.ChainID == chainID && res.SignerAddress == signerAddress && res.Nonce == nonce {
			return nil, fmt.Errorf("nonce %d already reserved on chain %d", nonce, chainID)
		}
	}

	id := randomUUID()
	now := time.Now().UTC()
	res := &db.SignerNonceReservation{
		ID:            id,
		BatchID:       batchID,
		ChainID:       chainID,
		SignerAddress: signerAddress,
		Nonce:         nonce,
		Status:        "ACTIVE",
		CreatedAt:     pgtype.Timestamptz{Time: now, Valid: true},
	}
	m.reservations[UUIDToString(id)] = res
	return res, nil
}

func (m *MockRepository) GetHighestNonceBySigner(ctx context.Context, chainID int64, signerAddress string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	maxNonce := int64(-1)
	for _, r := range m.reservations {
		if r.ChainID == chainID && r.SignerAddress == signerAddress && r.Nonce > maxNonce {
			maxNonce = r.Nonce
		}
	}
	return maxNonce, nil
}

func (m *MockRepository) GetActiveNonceReservation(ctx context.Context, batchID pgtype.UUID) (*db.SignerNonceReservation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.reservations {
		if UUIDToString(r.BatchID) == UUIDToString(batchID) && r.Status == "ACTIVE" {
			return r, nil
		}
	}
	return nil, fmt.Errorf("no active nonce reservation found")
}

func (m *MockRepository) CommitNonceReservation(ctx context.Context, reservationID pgtype.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reservations[UUIDToString(reservationID)]
	if !ok {
		return fmt.Errorf("reservation not found")
	}
	r.Status = "COMMITTED"
	r.CommittedAt = pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	return nil
}

func (m *MockRepository) ReleaseNonceReservation(ctx context.Context, reservationID pgtype.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reservations[UUIDToString(reservationID)]
	if !ok {
		return fmt.Errorf("reservation not found")
	}
	r.Status = "RELEASED"
	return nil
}

func (m *MockRepository) CreateBlockchainTransaction(ctx context.Context, arg db.CreateBlockchainTransactionParams) (*db.BlockchainTransaction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CreateTxErr != nil {
		return nil, m.CreateTxErr
	}

	// Enforce at most 1 active attempt (PREPARED or BROADCAST) per reservation
	resIDStr := UUIDToString(arg.NonceReservationID)
	for _, tx := range m.transactions {
		if UUIDToString(tx.NonceReservationID) == resIDStr && (tx.Status == "PREPARED" || tx.Status == "BROADCAST") {
			return nil, fmt.Errorf("an active transaction attempt already exists for reservation %s", resIDStr)
		}
	}

	txID := randomUUID()
	now := time.Now().UTC()
	tx := &db.BlockchainTransaction{
		ID:                      txID,
		BatchID:                 arg.BatchID,
		NonceReservationID:      arg.NonceReservationID,
		ReplacementSequence:     arg.ReplacementSequence,
		ChainID:                 arg.ChainID,
		FromAddress:             arg.FromAddress,
		ToAddress:               arg.ToAddress,
		Nonce:                   arg.Nonce,
		TransactionType:         arg.TransactionType,
		ValueWei:                arg.ValueWei,
		Calldata:                arg.Calldata,
		GasLimit:                arg.GasLimit,
		MaxFeePerGasWei:         arg.MaxFeePerGasWei,
		MaxPriorityFeePerGasWei: arg.MaxPriorityFeePerGasWei,
		TxHash:                  arg.TxHash,
		Status:                  "PREPARED",
		ReplacesTransactionID:   arg.ReplacesTransactionID,
		PreparedAt:              pgtype.Timestamptz{Time: now, Valid: true},
	}
	m.transactions[UUIDToString(txID)] = tx
	return tx, nil
}

func (m *MockRepository) GetActiveTransactionByReservationID(ctx context.Context, reservationID pgtype.UUID) (*db.BlockchainTransaction, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	resIDStr := UUIDToString(reservationID)
	for _, tx := range m.transactions {
		if UUIDToString(tx.NonceReservationID) == resIDStr && (tx.Status == "PREPARED" || tx.Status == "BROADCAST") {
			return tx, nil
		}
	}
	return nil, fmt.Errorf("no active transaction attempt found")
}

func (m *MockRepository) GetAuthoritativeTransactionForBatch(ctx context.Context, batchID pgtype.UUID) (*db.BlockchainTransaction, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.batches[UUIDToString(batchID)]
	if !ok || !b.AuthoritativeTransactionID.Valid {
		return nil, fmt.Errorf("no authoritative transaction found for batch")
	}
	tx, ok := m.transactions[UUIDToString(b.AuthoritativeTransactionID)]
	if !ok {
		return nil, fmt.Errorf("authoritative transaction not found")
	}
	return tx, nil
}

func (m *MockRepository) ListTransactionsByBatchID(ctx context.Context, batchID pgtype.UUID) ([]db.BlockchainTransaction, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	bIDStr := UUIDToString(batchID)
	list := make([]db.BlockchainTransaction, 0)
	for _, tx := range m.transactions {
		if UUIDToString(tx.BatchID) == bIDStr {
			list = append(list, *tx)
		}
	}
	return list, nil
}

func (m *MockRepository) MarkTransactionBroadcast(ctx context.Context, txID pgtype.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tx, ok := m.transactions[UUIDToString(txID)]
	if !ok {
		return fmt.Errorf("transaction not found")
	}
	tx.Status = "BROADCAST"
	tx.BroadcastAt = pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	return nil
}

func (m *MockRepository) MarkTransactionMined(ctx context.Context, txID pgtype.UUID, blockNumber int64, blockHash string, gasUsed int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tx, ok := m.transactions[UUIDToString(txID)]
	if !ok {
		return fmt.Errorf("transaction not found")
	}
	tx.Status = "MINED"
	tx.BlockNumber = pgtype.Int8{Int64: blockNumber, Valid: true}
	tx.BlockHash = pgtype.Text{String: blockHash, Valid: true}
	tx.GasUsed = pgtype.Int8{Int64: gasUsed, Valid: true}
	tx.MinedAt = pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	return nil
}

func (m *MockRepository) MarkTransactionReplaced(ctx context.Context, txID pgtype.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tx, ok := m.transactions[UUIDToString(txID)]
	if !ok {
		return fmt.Errorf("transaction not found")
	}
	tx.Status = "REPLACED"
	tx.ReplacedAt = pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	return nil
}

func (m *MockRepository) MarkTransactionFailed(ctx context.Context, txID pgtype.UUID, failureCode string, failureDetailCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tx, ok := m.transactions[UUIDToString(txID)]
	if !ok {
		return fmt.Errorf("transaction not found")
	}
	tx.Status = "FAILED"
	tx.FailureCode = pgtype.Text{String: failureCode, Valid: true}
	tx.FailureDetailCode = pgtype.Text{String: failureDetailCode, Valid: true}
	tx.FailedAt = pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	return nil
}

func (m *MockRepository) GetBatchCertificateByPublicID(ctx context.Context, publicID string) (*db.BatchCertificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	bc, ok := m.batchCerts[publicID]
	if !ok {
		return nil, fmt.Errorf("batch certificate not found")
	}
	return bc, nil
}

func (m *MockRepository) GetProofNodesByBatchCertID(ctx context.Context, batchCertID pgtype.UUID) ([]db.GetProofNodesByBatchCertIDRow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	nodes, ok := m.proofNodes[UUIDToString(batchCertID)]
	if !ok {
		return []db.GetProofNodesByBatchCertIDRow{}, nil
	}
	return nodes, nil
}

func (m *MockRepository) GetCertificateByPublicID(ctx context.Context, publicID string) (*CertificateRow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.GetCertByPublicIDErr != nil {
		return nil, m.GetCertByPublicIDErr
	}
	c, ok := m.certificates[publicID]
	if !ok {
		return nil, fmt.Errorf("certificate not found")
	}
	return c, nil
}

func randomUUID() pgtype.UUID {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return pgtype.UUID{Bytes: b, Valid: true}
}
