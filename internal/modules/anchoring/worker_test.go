package anchoring

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/blockchain"
)

const (
	testSignerPrivKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testSignerAddress = "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c"
)

func noopSleeper(d time.Duration) {}

func newTestSigner(t *testing.T) blockchain.Signer {
	signer, err := blockchain.NewDeterministicSigner(testSignerAddress, 80002, testSignerPrivKey)
	if err != nil {
		t.Fatalf("failed to create test signer: %v", err)
	}
	return signer
}

func setupTestBatch(repo *MockRepository) (*db.MerkleBatch, [32]byte, [32]byte) {
	batchID := randomUUID()
	var root [32]byte
	var canonID [32]byte
	root[0] = 0x11
	canonID[0] = 0x22

	batch := &db.MerkleBatch{
		ID:               batchID,
		BatchNumber:      1,
		CanonicalBatchID: "0x" + hex.EncodeToString(canonID[:]),
		Status:           "READY",
		MerkleRoot:       pgtype.Text{String: "0x" + hex.EncodeToString(root[:]), Valid: true},
		LeafCount:        5,
		CreatedAt:        pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
	}
	repo.batches[UUIDToString(batchID)] = batch
	return batch, root, canonID
}

func TestWorker_FullLifecycle_Success(t *testing.T) {
	repo := NewMockRepository()
	client := blockchain.NewMockBlockchainClient()
	signer := newTestSigner(t)

	batch, root, canonID := setupTestBatch(repo)

	contractAddr := "0x5FbDB2315678afecb367f032d93F642f64180aa3"
	cfg := WorkerConfig{
		WorkerID:              "test-worker-1",
		ChainID:               80002,
		ContractAddress:       contractAddr,
		SignerAddress:         signer.Address(),
		ConfirmationsRequired: 2,
		PollInterval:          10 * time.Millisecond,
		ConfirmationTimeout:   100 * time.Millisecond,
		BatchLeaseDuration:    60 * time.Second,
		MaxRetries:            2,
		FeeBumpPercentage:     15,
	}

	worker := NewWorker(repo, client, signer, cfg, noopSleeper, newTestLogger())

	// Run next batch in a goroutine
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Pre-stage mock receipt on the mock client once broadcast occurs
	go func() {
		for {
			if client.BroadcastCount() > 0 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}

		repo.mu.RLock()
		var activeTx *db.BlockchainTransaction
		for _, tx := range repo.transactions {
			activeTx = tx
			break
		}
		repo.mu.RUnlock()

		if activeTx != nil {
			client.AddMockReceipt(activeTx.TxHash, contractAddr, root, canonID, signer.Address(), 5, 10, "0xblock10")
			client.SetBlockHeight(15) // 6 confirmations
		}
	}()

	processed, err := worker.ProcessNextBatch(ctx)
	if err != nil {
		t.Fatalf("expected batch processing success, got: %v", err)
	}
	if !processed {
		t.Fatalf("expected batch to be processed")
	}

	// Verify batch status is CONFIRMED
	finalBatch := repo.batches[UUIDToString(batch.ID)]
	if finalBatch.Status != "CONFIRMED" {
		t.Errorf("expected batch status CONFIRMED, got %s", finalBatch.Status)
	}
	if !finalBatch.BlockNumber.Valid || finalBatch.BlockNumber.Int64 != 10 {
		t.Errorf("expected mined block 10, got %v", finalBatch.BlockNumber)
	}

	// Verify transaction status is MINED
	repo.mu.RLock()
	var minedTx *db.BlockchainTransaction
	for _, tx := range repo.transactions {
		minedTx = tx
		break
	}
	repo.mu.RUnlock()

	if minedTx == nil || minedTx.Status != "MINED" {
		t.Errorf("expected transaction to be MINED, got %v", minedTx)
	}

	// Verify nonce reservation is COMMITTED
	repo.mu.RLock()
	var committedRes *db.SignerNonceReservation
	for _, r := range repo.reservations {
		if UUIDToString(r.BatchID) == UUIDToString(batch.ID) {
			committedRes = r
			break
		}
	}
	repo.mu.RUnlock()

	if committedRes == nil || committedRes.Status != "COMMITTED" {
		t.Errorf("expected reservation status COMMITTED, got %v", committedRes)
	}
}

func TestWorker_CrashRecovery_PREPARED_BeforeBroadcast(t *testing.T) {
	repo := NewMockRepository()
	client := blockchain.NewMockBlockchainClient()
	signer := newTestSigner(t)

	batch, root, canonID := setupTestBatch(repo)
	contractAddr := "0x5FbDB2315678afecb367f032d93F642f64180aa3"

	// Simulate crash state: active nonce reservation and PREPARED transaction already exist
	resID := randomUUID()
	repo.reservations[UUIDToString(resID)] = &db.SignerNonceReservation{
		ID:            resID,
		BatchID:       batch.ID,
		ChainID:       80002,
		SignerAddress: signer.Address(),
		Nonce:         7,
		Status:        "ACTIVE",
	}

	calldata := blockchain.EncodeAnchorRootCalldata(root, canonID, 5)
	unsignedTx := &blockchain.UnsignedTx{
		ChainID:              big.NewInt(80002),
		Nonce:                7,
		MaxPriorityFeePerGas: big.NewInt(1500000000),
		MaxFeePerGas:         big.NewInt(3500000000),
		GasLimit:             150000,
		To:                   contractAddr,
		Value:                big.NewInt(0),
		Data:                 calldata,
	}
	_, predHash, _ := signer.SignTransaction(unsignedTx)

	txID := randomUUID()
	repo.transactions[UUIDToString(txID)] = &db.BlockchainTransaction{
		ID:                      txID,
		BatchID:                 batch.ID,
		NonceReservationID:      resID,
		ReplacementSequence:     0,
		ChainID:                 80002,
		FromAddress:             signer.Address(),
		ToAddress:               contractAddr,
		Nonce:                   7,
		TransactionType:         2,
		Calldata:                calldata,
		GasLimit:                150000,
		MaxFeePerGasWei:         bigIntToNumeric(big.NewInt(3500000000)),
		MaxPriorityFeePerGasWei: bigIntToNumeric(big.NewInt(1500000000)),
		TxHash:                  predHash,
		Status:                  "PREPARED",
	}
	batch.AuthoritativeTransactionID = txID

	// Pre-stage receipt
	client.AddMockReceipt(predHash, contractAddr, root, canonID, signer.Address(), 5, 20, "0xblock20")
	client.SetBlockHeight(22)

	cfg := WorkerConfig{
		WorkerID:              "recovery-worker",
		ChainID:               80002,
		ContractAddress:       contractAddr,
		SignerAddress:         signer.Address(),
		ConfirmationsRequired: 2,
		PollInterval:          5 * time.Millisecond,
		ConfirmationTimeout:   50 * time.Millisecond,
		BatchLeaseDuration:    60 * time.Second,
		MaxRetries:            1,
		FeeBumpPercentage:     15,
	}

	worker := NewWorker(repo, client, signer, cfg, noopSleeper, newTestLogger())

	// Focused recovery assertion: proving a PREPARED transaction reconstructed
	// solely from persisted fields reproduces its stored tx_hash exactly before broadcast.
	persistedTx := repo.transactions[UUIDToString(txID)]
	reconstructedTx, bErr := worker.buildUnsignedTx(
		batch,
		persistedTx.Nonce,
		persistedTx.Calldata,
		persistedTx.GasLimit,
		persistedTx.MaxFeePerGasWei,
		persistedTx.MaxPriorityFeePerGasWei,
	)
	if bErr != nil {
		t.Fatalf("failed to build unsigned transaction: %v", bErr)
	}
	reconstructedRawHex, reconstructedHash, err := signer.SignTransaction(reconstructedTx)
	if err != nil {
		t.Fatalf("failed to sign reconstructed transaction: %v", err)
	}
	if reconstructedHash != persistedTx.TxHash {
		t.Fatalf("reconstructed transaction hash mismatch from persisted fields: expected %s, got %s", persistedTx.TxHash, reconstructedHash)
	}
	if len(reconstructedRawHex) == 0 {
		t.Fatalf("expected non-empty reconstructed raw signed hex")
	}

	processed, err := worker.ProcessNextBatch(context.Background())
	if err != nil {
		t.Fatalf("expected clean PREPARED recovery, got: %v", err)
	}
	if !processed {
		t.Fatalf("expected batch to be processed")
	}

	if repo.batches[UUIDToString(batch.ID)].Status != "CONFIRMED" {
		t.Errorf("expected CONFIRMED status after recovery")
	}
}

func TestWorker_ReceiptFailure_Reverted(t *testing.T) {
	repo := NewMockRepository()
	client := blockchain.NewMockBlockchainClient()
	signer := newTestSigner(t)

	batch, _, _ := setupTestBatch(repo)
	contractAddr := "0x5FbDB2315678afecb367f032d93F642f64180aa3"

	bgErrCh := make(chan error, 1)

	// Mock receipt with Status = 0 (reverted)
	go func() {
		for {
			if client.BroadcastCount() > 0 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		repo.mu.RLock()
		var activeTx *db.BlockchainTransaction
		for _, tx := range repo.transactions {
			activeTx = tx
			break
		}
		repo.mu.RUnlock()

		if activeTx != nil {
			client.AddMockRevertedReceipt(activeTx.TxHash, contractAddr, 10, "0xblock10")
			client.SetBlockHeight(15)
		}
		bgErrCh <- nil
	}()

	cfg := WorkerConfig{
		WorkerID:              "test-worker-revert",
		ChainID:               80002,
		ContractAddress:       contractAddr,
		SignerAddress:         signer.Address(),
		ConfirmationsRequired: 2,
		PollInterval:          5 * time.Millisecond,
		ConfirmationTimeout:   50 * time.Millisecond,
		BatchLeaseDuration:    60 * time.Second,
		MaxRetries:            1,
		FeeBumpPercentage:     15,
	}

	worker := NewWorker(repo, client, signer, cfg, noopSleeper, newTestLogger())
	_, err := worker.ProcessNextBatch(context.Background())

	// Check background goroutine results
	select {
	case bgErr := <-bgErrCh:
		if bgErr != nil {
			t.Fatalf("background goroutine failure: %v", bgErr)
		}
	default:
	}
	if err == nil {
		t.Fatalf("expected error on reverted receipt, got nil")
	}

	finalBatch := repo.batches[UUIDToString(batch.ID)]
	if finalBatch.Status != "FAILED" {
		t.Errorf("expected batch status FAILED, got %s", finalBatch.Status)
	}
}

func TestWorker_EventMismatch_WrongRoot(t *testing.T) {
	repo := NewMockRepository()
	client := blockchain.NewMockBlockchainClient()
	signer := newTestSigner(t)

	batch, _, canonID := setupTestBatch(repo)
	contractAddr := "0x5FbDB2315678afecb367f032d93F642f64180aa3"

	// Mock receipt with wrong root
	var wrongRoot [32]byte
	wrongRoot[0] = 0x99

	go func() {
		for {
			if client.BroadcastCount() > 0 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		repo.mu.RLock()
		var activeTx *db.BlockchainTransaction
		for _, tx := range repo.transactions {
			activeTx = tx
			break
		}
		repo.mu.RUnlock()

		if activeTx != nil {
			client.AddMockReceipt(activeTx.TxHash, contractAddr, wrongRoot, canonID, signer.Address(), 5, 10, "0xblock10")
			client.SetBlockHeight(15)
		}
	}()

	cfg := WorkerConfig{
		WorkerID:              "test-worker-root-mismatch",
		ChainID:               80002,
		ContractAddress:       contractAddr,
		SignerAddress:         signer.Address(),
		ConfirmationsRequired: 2,
		PollInterval:          5 * time.Millisecond,
		ConfirmationTimeout:   50 * time.Millisecond,
		BatchLeaseDuration:    60 * time.Second,
		MaxRetries:            1,
		FeeBumpPercentage:     15,
	}

	worker := NewWorker(repo, client, signer, cfg, noopSleeper, newTestLogger())
	_, err := worker.ProcessNextBatch(context.Background())
	if err == nil {
		t.Fatalf("expected error on root mismatch, got nil")
	}

	if repo.batches[UUIDToString(batch.ID)].Status != "FAILED" {
		t.Errorf("expected batch status FAILED on root mismatch")
	}
}

func TestWorker_ReorgDetection(t *testing.T) {
	repo := NewMockRepository()
	client := blockchain.NewMockBlockchainClient()
	signer := newTestSigner(t)

	batch, root, canonID := setupTestBatch(repo)
	contractAddr := "0x5FbDB2315678afecb367f032d93F642f64180aa3"

	// Mock receipt has BlockHash "0xhashA", but header has "0xhashB" (reorg!)
	go func() {
		for {
			if client.BroadcastCount() > 0 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		repo.mu.RLock()
		var activeTx *db.BlockchainTransaction
		for _, tx := range repo.transactions {
			activeTx = tx
			break
		}
		repo.mu.RUnlock()

		if activeTx != nil {
			client.AddMockReceipt(activeTx.TxHash, contractAddr, root, canonID, signer.Address(), 5, 10, "0xhashA")
			// Simulate reorg in canonical header
			client.SetBlockHeader(10, &blockchain.BlockHeader{
				Number: 10,
				Hash:   "0xhashB_reorganized",
			})
			client.SetBlockHeight(15)
		}
	}()

	cfg := WorkerConfig{
		WorkerID:              "test-worker-reorg",
		ChainID:               80002,
		ContractAddress:       contractAddr,
		SignerAddress:         signer.Address(),
		ConfirmationsRequired: 2,
		PollInterval:          5 * time.Millisecond,
		ConfirmationTimeout:   50 * time.Millisecond,
		BatchLeaseDuration:    60 * time.Second,
		MaxRetries:            1,
		FeeBumpPercentage:     15,
	}

	worker := NewWorker(repo, client, signer, cfg, noopSleeper, newTestLogger())
	_, err := worker.ProcessNextBatch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "reorganization") {
		t.Fatalf("expected reorg error, got: %v", err)
	}

	if repo.batches[UUIDToString(batch.ID)].Status != "FAILED" {
		t.Errorf("expected batch status FAILED on reorg")
	}
}

func TestWorker_EIP1559_ReplacementAttempt(t *testing.T) {
	repo := NewMockRepository()
	client := blockchain.NewMockBlockchainClient()
	signer := newTestSigner(t)

	batch, root, canonID := setupTestBatch(repo)
	contractAddr := "0x5FbDB2315678afecb367f032d93F642f64180aa3"

	// Don't provide receipt on first attempt, but provide receipt on second (replacement) attempt
	go func() {
		// Wait for 2nd broadcast (replacement)
		for {
			if client.BroadcastCount() >= 2 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}

		repo.mu.RLock()
		var replacementTx *db.BlockchainTransaction
		for _, tx := range repo.transactions {
			if tx.ReplacementSequence == 1 {
				replacementTx = tx
				break
			}
		}
		repo.mu.RUnlock()

		if replacementTx != nil {
			client.AddMockReceipt(replacementTx.TxHash, contractAddr, root, canonID, signer.Address(), 5, 30, "0xblock30")
			client.SetBlockHeight(35)
		}
	}()

	cfg := WorkerConfig{
		WorkerID:              "test-worker-replace",
		ChainID:               80002,
		ContractAddress:       contractAddr,
		SignerAddress:         signer.Address(),
		ConfirmationsRequired: 2,
		PollInterval:          5 * time.Millisecond,
		ConfirmationTimeout:   30 * time.Millisecond, // Short timeout triggers replacement
		BatchLeaseDuration:    60 * time.Second,
		MaxRetries:            2,
		FeeBumpPercentage:     15,
	}

	worker := NewWorker(repo, client, signer, cfg, noopSleeper, newTestLogger())
	processed, err := worker.ProcessNextBatch(context.Background())
	if err != nil {
		t.Fatalf("expected replacement success, got: %v", err)
	}
	if !processed {
		t.Fatalf("expected batch to be processed")
	}

	// Verify replacement sequence 1 exists and reused same nonce
	var tx0, tx1 *db.BlockchainTransaction
	for _, tx := range repo.transactions {
		if tx.ReplacementSequence == 0 {
			tx0 = tx
		} else if tx.ReplacementSequence == 1 {
			tx1 = tx
		}
	}

	if tx0 == nil || tx1 == nil {
		t.Fatalf("expected both original (seq 0) and replacement (seq 1) transactions")
	}

	if tx0.Status != "REPLACED" {
		t.Errorf("expected tx0 status REPLACED, got %s", tx0.Status)
	}
	if tx1.Status != "MINED" {
		t.Errorf("expected tx1 status MINED, got %s", tx1.Status)
	}
	if tx0.Nonce != tx1.Nonce {
		t.Errorf("replacement attempt must reuse identical nonce: %d vs %d", tx0.Nonce, tx1.Nonce)
	}
	if UUIDToString(tx0.NonceReservationID) != UUIDToString(tx1.NonceReservationID) {
		t.Errorf("replacement attempt must reuse identical nonce reservation ID")
	}

	// Verify replacement fees are strictly higher by configured percentage and at least 1 wei
	maxFee0, err0 := numericToBigInt(tx0.MaxFeePerGasWei)
	maxFee1, err1 := numericToBigInt(tx1.MaxFeePerGasWei)
	if err0 != nil || err1 != nil {
		t.Fatalf("failed to decode fees: %v, %v", err0, err1)
	}
	if maxFee1.Cmp(maxFee0) <= 0 {
		t.Errorf("replacement maxFee must be strictly higher: %s vs %s", maxFee1.String(), maxFee0.String())
	}

	finalBatch := repo.batches[UUIDToString(batch.ID)]
	if finalBatch.Status != "CONFIRMED" {
		t.Errorf("expected batch status CONFIRMED after replacement, got %s", finalBatch.Status)
	}
	if UUIDToString(finalBatch.AuthoritativeTransactionID) != UUIDToString(tx1.ID) {
		t.Errorf("expected authoritative transaction to be replacement tx1")
	}
}

func TestWorker_BoundedRetryExhaustion(t *testing.T) {
	repo := NewMockRepository()
	client := blockchain.NewMockBlockchainClient()
	signer := newTestSigner(t)

	batch, _, _ := setupTestBatch(repo)
	contractAddr := "0x5FbDB2315678afecb367f032d93F642f64180aa3"

	// Never provide receipt -> triggers retry exhaustion
	cfg := WorkerConfig{
		WorkerID:              "test-worker-exhaust",
		ChainID:               80002,
		ContractAddress:       contractAddr,
		SignerAddress:         signer.Address(),
		ConfirmationsRequired: 2,
		PollInterval:          5 * time.Millisecond,
		ConfirmationTimeout:   20 * time.Millisecond,
		BatchLeaseDuration:    60 * time.Second,
		MaxRetries:            1,
		FeeBumpPercentage:     15,
	}

	worker := NewWorker(repo, client, signer, cfg, noopSleeper, newTestLogger())
	_, err := worker.ProcessNextBatch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "timed out after") {
		t.Fatalf("expected timeout error on retry exhaustion, got: %v", err)
	}

	finalBatch := repo.batches[UUIDToString(batch.ID)]
	if finalBatch.Status != "FAILED" {
		t.Errorf("expected batch status FAILED after exhaustion, got %s", finalBatch.Status)
	}
	if finalBatch.FailureCode.String != "RETRIES_EXHAUSTED" {
		t.Errorf("expected failure code RETRIES_EXHAUSTED, got %s", finalBatch.FailureCode.String)
	}
}

func TestWorker_ContextCancellation(t *testing.T) {
	repo := NewMockRepository()
	client := blockchain.NewMockBlockchainClient()
	signer := newTestSigner(t)

	_, _, _ = setupTestBatch(repo)
	contractAddr := "0x5FbDB2315678afecb367f032d93F642f64180aa3"

	cfg := WorkerConfig{
		WorkerID:              "test-worker-cancel",
		ChainID:               80002,
		ContractAddress:       contractAddr,
		SignerAddress:         signer.Address(),
		ConfirmationsRequired: 2,
		PollInterval:          50 * time.Millisecond,
		ConfirmationTimeout:   5 * time.Second,
		BatchLeaseDuration:    60 * time.Second,
		MaxRetries:            1,
		FeeBumpPercentage:     15,
	}

	worker := NewWorker(repo, client, signer, cfg, noopSleeper, newTestLogger())

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel context quickly
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := worker.Run(ctx)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestNumericToBigInt_RoundTrip(t *testing.T) {
	testValues := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(15),
		big.NewInt(35),
		big.NewInt(1500000000), // 1.5 Gwei (has trailing zeroes)
		big.NewInt(3500000000), // 3.5 Gwei (has trailing zeroes)
		new(big.Int).Mul(big.NewInt(1000000000000000000), big.NewInt(10)), // 10 ETH
	}

	for _, original := range testValues {
		num := bigIntToNumeric(original)
		reconstructed, err := numericToBigInt(num)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", original.String(), err)
		}
		if original.Cmp(reconstructed) != 0 {
			t.Errorf("numeric roundtrip failed for %s: got %s", original.String(), reconstructed.String())
		}
	}
}

func TestNumericToBigInt_ValidationAndErrors(t *testing.T) {
	// 1. Invalid / SQL NULL
	if _, err := numericToBigInt(pgtype.Numeric{Valid: false}); err == nil {
		t.Errorf("expected error for invalid/NULL numeric")
	}

	// 2. NaN
	if _, err := numericToBigInt(pgtype.Numeric{Valid: true, NaN: true}); err == nil {
		t.Errorf("expected error for NaN numeric")
	}

	// 3. Infinity
	if _, err := numericToBigInt(pgtype.Numeric{Valid: true, InfinityModifier: pgtype.Infinity}); err == nil {
		t.Errorf("expected error for Infinity numeric")
	}

	// 4. Negative Infinity
	if _, err := numericToBigInt(pgtype.Numeric{Valid: true, InfinityModifier: pgtype.NegativeInfinity}); err == nil {
		t.Errorf("expected error for NegativeInfinity numeric")
	}

	// 5. Nil Int
	if _, err := numericToBigInt(pgtype.Numeric{Valid: true, Int: nil}); err == nil {
		t.Errorf("expected error for nil Int numeric")
	}

	// 6. Negative values
	if _, err := numericToBigInt(pgtype.Numeric{Valid: true, Int: big.NewInt(-1)}); err == nil {
		t.Errorf("expected error for negative numeric")
	}

	// 7. Fractional remainder: 1.5 wei (15 with Exp -1)
	if _, err := numericToBigInt(pgtype.Numeric{Valid: true, Int: big.NewInt(15), Exp: -1}); err == nil {
		t.Errorf("expected error for fractional wei with remainder")
	}

	// 8. Fractional without remainder: 1500 with Exp -2 = 15 wei
	val, err := numericToBigInt(pgtype.Numeric{Valid: true, Int: big.NewInt(1500), Exp: -2})
	if err != nil || val.Int64() != 15 {
		t.Errorf("expected clean conversion of 1500e-2 to 15, got %v (err: %v)", val, err)
	}

	// 9. Exact uint256 max (2^256 - 1)
	maxUint := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	val, err = numericToBigInt(pgtype.Numeric{Valid: true, Int: maxUint})
	if err != nil || val.Cmp(maxUint) != 0 {
		t.Errorf("expected success for uint256 max, got %v (err: %v)", val, err)
	}

	// 10. Exceeding uint256 max (2^256)
	overflowUint := new(big.Int).Lsh(big.NewInt(1), 256)
	if _, err := numericToBigInt(pgtype.Numeric{Valid: true, Int: overflowUint}); err == nil {
		t.Errorf("expected error for value exceeding uint256 max")
	}
}

func TestWorker_CorruptedPersistence_AbortBeforeBroadcast(t *testing.T) {
	repo := NewMockRepository()
	client := blockchain.NewMockBlockchainClient()
	signer := newTestSigner(t)

	batch, root, canonID := setupTestBatch(repo)
	contractAddr := "0x5FbDB2315678afecb367f032d93F642f64180aa3"

	resID := randomUUID()
	repo.reservations[UUIDToString(resID)] = &db.SignerNonceReservation{
		ID:            resID,
		BatchID:       batch.ID,
		ChainID:       80002,
		SignerAddress: signer.Address(),
		Nonce:         12,
		Status:        "ACTIVE",
	}

	calldata := blockchain.EncodeAnchorRootCalldata(root, canonID, 5)
	txID := randomUUID()
	// Persist corrupted attempt where stored TxHash does NOT match the reconstructed hash
	repo.transactions[UUIDToString(txID)] = &db.BlockchainTransaction{
		ID:                      txID,
		BatchID:                 batch.ID,
		NonceReservationID:      resID,
		ReplacementSequence:     0,
		ChainID:                 80002,
		FromAddress:             signer.Address(),
		ToAddress:               contractAddr,
		Nonce:                   12,
		TransactionType:         2,
		Calldata:                calldata,
		GasLimit:                150000,
		MaxFeePerGasWei:         bigIntToNumeric(big.NewInt(3500000000)),
		MaxPriorityFeePerGasWei: bigIntToNumeric(big.NewInt(1500000000)),
		TxHash:                  "0x000000000000000000000000000000000000000000000000000000000000dead", // Corrupted!
		Status:                  "PREPARED",
	}
	batch.AuthoritativeTransactionID = txID

	cfg := WorkerConfig{
		WorkerID:              "corrupt-worker",
		ChainID:               80002,
		ContractAddress:       contractAddr,
		SignerAddress:         signer.Address(),
		ConfirmationsRequired: 2,
		PollInterval:          5 * time.Millisecond,
		ConfirmationTimeout:   50 * time.Millisecond,
		BatchLeaseDuration:    60 * time.Second,
		MaxRetries:            1,
		FeeBumpPercentage:     15,
	}

	worker := NewWorker(repo, client, signer, cfg, noopSleeper, newTestLogger())
	_, err := worker.ProcessNextBatch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "reconstructed tx hash mismatch") {
		t.Fatalf("expected reconstructed tx hash mismatch error, got: %v", err)
	}

	// Verify zero broadcasts occurred
	if client.BroadcastCount() != 0 {
		t.Errorf("expected 0 broadcasts on corrupted persistence, got %d", client.BroadcastCount())
	}
}

func TestWorker_NumericFailure_ZeroPersistenceZeroBroadcast(t *testing.T) {
	repo := NewMockRepository()
	client := blockchain.NewMockBlockchainClient()
	// Set mock fee data to negative fee
	client.SetFeeData(&blockchain.FeeData{
		BaseFee:              big.NewInt(1000000000),
		MaxPriorityFeePerGas: big.NewInt(-1), // Invalid negative tip!
		MaxFeePerGas:         big.NewInt(3000000000),
	})

	signer := newTestSigner(t)
	_, _, _ = setupTestBatch(repo)
	contractAddr := "0x5FbDB2315678afecb367f032d93F642f64180aa3"

	cfg := WorkerConfig{
		WorkerID:              "numeric-fail-worker",
		ChainID:               80002,
		ContractAddress:       contractAddr,
		SignerAddress:         signer.Address(),
		ConfirmationsRequired: 2,
		PollInterval:          5 * time.Millisecond,
		ConfirmationTimeout:   50 * time.Millisecond,
		BatchLeaseDuration:    60 * time.Second,
		MaxRetries:            1,
		FeeBumpPercentage:     15,
	}

	worker := NewWorker(repo, client, signer, cfg, noopSleeper, newTestLogger())
	_, err := worker.ProcessNextBatch(context.Background())
	if err == nil {
		t.Fatalf("expected error on negative fee data, got nil")
	}

	// Verify zero persistence in repo.transactions
	if len(repo.transactions) != 0 {
		t.Errorf("expected 0 transactions persisted on numeric failure, got %d", len(repo.transactions))
	}
	// Verify zero broadcasts
	if client.BroadcastCount() != 0 {
		t.Errorf("expected 0 broadcasts on numeric failure, got %d", client.BroadcastCount())
	}
}
