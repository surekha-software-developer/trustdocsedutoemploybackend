package anchoring

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/blockchain"
)

// Sleeper defines sleep abstraction to enable deterministic zero-delay testing.
type Sleeper func(d time.Duration)

// WorkerConfig contains settings governing the background anchoring worker lifecycle.
type WorkerConfig struct {
	WorkerID              string
	ChainID               int64
	ContractAddress       string
	SignerAddress         string
	ConfirmationsRequired int
	PollInterval          time.Duration
	ConfirmationTimeout   time.Duration
	BatchLeaseDuration    time.Duration
	MaxRetries            int
	FeeBumpPercentage     int
}

// Worker executes crash-safe Merkle batch submission, receipt polling, and confirmation.
type Worker struct {
	repo    Repository
	client  blockchain.BlockchainClient
	signer  blockchain.Signer
	cfg     WorkerConfig
	sleeper Sleeper
	logger  *slog.Logger
}

// NewWorker constructs a new anchoring Worker instance.
func NewWorker(
	repo Repository,
	client blockchain.BlockchainClient,
	signer blockchain.Signer,
	cfg WorkerConfig,
	sleeper Sleeper,
	logger *slog.Logger,
) *Worker {
	if cfg.WorkerID == "" {
		host, _ := os.Hostname()
		var randBytes [4]byte
		_, _ = rand.Read(randBytes[:])
		cfg.WorkerID = fmt.Sprintf("%s:%d:%s", host, os.Getpid(), hex.EncodeToString(randBytes[:]))
	}
	if cfg.ConfirmationsRequired <= 0 {
		cfg.ConfirmationsRequired = 2
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.ConfirmationTimeout <= 0 {
		cfg.ConfirmationTimeout = 5 * time.Minute
	}
	if cfg.BatchLeaseDuration <= 0 {
		cfg.BatchLeaseDuration = 60 * time.Second
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 5
	}
	if cfg.FeeBumpPercentage < 10 {
		cfg.FeeBumpPercentage = 15
	}
	if sleeper == nil {
		sleeper = time.Sleep
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Worker{
		repo:    repo,
		client:  client,
		signer:  signer,
		cfg:     cfg,
		sleeper: sleeper,
		logger:  logger,
	}
}

// ProcessNextBatch claims and processes a single batch. Returns true if a batch was processed.
func (w *Worker) ProcessNextBatch(ctx context.Context) (bool, error) {
	leaseSeconds := int32(w.cfg.BatchLeaseDuration.Seconds())

	// 1. Claim work using bounded lease
	batch, err := w.repo.ClaimNextReadyBatch(ctx, w.cfg.WorkerID, leaseSeconds, w.cfg.ChainID, w.cfg.ContractAddress)
	if err != nil {
		// No ready work available
		return false, nil
	}

	w.logger.Info("claimed batch for submission",
		"batch_id", UUIDToString(batch.ID),
		"canonical_batch_id", batch.CanonicalBatchID,
		"claimed_by", w.cfg.WorkerID,
	)

	// Process claimed batch through its lifecycle
	if err := w.processBatch(ctx, batch); err != nil {
		w.logger.Error("batch processing failed",
			"batch_id", UUIDToString(batch.ID),
			"error", err,
		)
		return true, err
	}

	return true, nil
}

// Run executes the worker processing loop until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	w.logger.Info("starting anchoring worker",
		"worker_id", w.cfg.WorkerID,
		"chain_id", w.cfg.ChainID,
		"contract_address", w.cfg.ContractAddress,
		"signer_address", w.cfg.SignerAddress,
	)

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("anchoring worker stopped cleanly by context cancellation")
			return ctx.Err()
		default:
			processed, err := w.ProcessNextBatch(ctx)
			if err != nil {
				w.logger.Warn("error in worker tick", "error", err)
			}
			if !processed {
				// No work claimed; back off bounded poll interval
				w.sleeper(w.cfg.PollInterval)
			}
		}
	}
}

func (w *Worker) processBatch(ctx context.Context, batch *db.MerkleBatch) error {
	// 1. Acquire or recover nonce reservation
	reservation, err := w.acquireOrRecoverNonceReservation(ctx, batch)
	if err != nil {
		_ = w.repo.MarkBatchFailed(ctx, batch.ID, "SUBMISSION", "NONCE_RESERVATION_FAILED", "UNABLE_TO_RESERVE_NONCE")
		return fmt.Errorf("nonce reservation failed: %w", err)
	}

	// 2. Prepare or recover transaction attempt
	tx, signedRawHex, err := w.prepareOrRecoverTransaction(ctx, batch, reservation)
	if err != nil {
		_ = w.repo.MarkBatchFailed(ctx, batch.ID, "SUBMISSION", "TX_PREPARATION_FAILED", "TRANSACTION_CONSTRUCTION_ERROR")
		return fmt.Errorf("transaction preparation failed: %w", err)
	}

	// 3. Broadcast transaction if still PREPARED
	if tx.Status == "PREPARED" {
		broadcastHash, bErr := w.client.BroadcastTransaction(ctx, signedRawHex)
		if bErr != nil {
			w.logger.Warn("broadcast transaction error, will reconcile by predicted hash",
				"predicted_tx_hash", tx.TxHash,
				"error", bErr,
			)
		} else if broadcastHash != "" && broadcastHash != tx.TxHash {
			_ = w.repo.MarkBatchFailed(ctx, batch.ID, "SUBMISSION", "TX_HASH_MISMATCH", "BROADCAST_HASH_MISMATCH")
			return fmt.Errorf("broadcast hash mismatch: predicted %s, got %s", tx.TxHash, broadcastHash)
		}

		if err := w.repo.MarkTransactionBroadcast(ctx, tx.ID); err != nil {
			w.logger.Warn("failed to mark transaction BROADCAST in db", "error", err)
		}
		if err := w.repo.MarkBatchSubmitted(ctx, batch.ID); err != nil {
			w.logger.Warn("failed to mark batch SUBMITTED in db", "error", err)
		}
	}

	// 4. Poll receipt, handle replacements, and confirm
	return w.pollReceiptAndConfirm(ctx, batch, reservation, tx)
}

func (w *Worker) acquireOrRecoverNonceReservation(ctx context.Context, batch *db.MerkleBatch) (*db.SignerNonceReservation, error) {
	// Check if this batch already has an active reservation
	res, err := w.repo.GetActiveNonceReservation(ctx, batch.ID)
	if err == nil && res != nil {
		return res, nil
	}

	// Determine next nonce: max(chain_pending_nonce, db_highest_nonce + 1)
	chainPendingNonce, err := w.client.GetPendingNonce(ctx, w.cfg.SignerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pending nonce from chain: %w", err)
	}

	dbHighestNonce, err := w.repo.GetHighestNonceBySigner(ctx, w.cfg.ChainID, w.cfg.SignerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to query highest nonce from db: %w", err)
	}

	nextNonce := int64(chainPendingNonce)
	if dbHighestNonce >= nextNonce {
		nextNonce = dbHighestNonce + 1
	}

	return w.repo.ReserveSignerNonce(ctx, batch.ID, w.cfg.ChainID, w.cfg.SignerAddress, nextNonce)
}

func (w *Worker) prepareOrRecoverTransaction(
	ctx context.Context,
	batch *db.MerkleBatch,
	reservation *db.SignerNonceReservation,
) (*db.BlockchainTransaction, string, error) {
	// Check if active transaction attempt already exists
	activeTx, err := w.repo.GetActiveTransactionByReservationID(ctx, reservation.ID)
	if err == nil && activeTx != nil {
		// Reconstruct raw signed payload deterministically
		unsignedTx, bErr := w.buildUnsignedTx(batch, reservation.Nonce, activeTx.Calldata, activeTx.GasLimit, activeTx.MaxFeePerGasWei, activeTx.MaxPriorityFeePerGasWei)
		if bErr != nil {
			return nil, "", fmt.Errorf("failed to reconstruct unsigned transaction: %w", bErr)
		}
		signedRawHex, predictedHash, err := w.signer.SignTransaction(unsignedTx)
		if err != nil {
			return nil, "", fmt.Errorf("failed to reconstruct signed transaction: %w", err)
		}
		if predictedHash != activeTx.TxHash {
			return nil, "", fmt.Errorf("reconstructed tx hash mismatch: expected %s, got %s", activeTx.TxHash, predictedHash)
		}
		return activeTx, signedRawHex, nil
	}

	// Prepare fresh transaction attempt
	rootBytes, err := hexTo32Bytes(batch.MerkleRoot.String)
	if err != nil {
		return nil, "", fmt.Errorf("invalid batch merkle root: %w", err)
	}
	batchIDBytes, err := hexTo32Bytes(batch.CanonicalBatchID)
	if err != nil {
		return nil, "", fmt.Errorf("invalid batch canonical ID: %w", err)
	}

	calldata := blockchain.EncodeAnchorRootCalldata(rootBytes, batchIDBytes, uint32(batch.LeafCount))

	// Estimate gas and fetch fee data
	gasLimit, err := w.client.EstimateGas(ctx, blockchain.CallMsg{
		From: w.cfg.SignerAddress,
		To:   w.cfg.ContractAddress,
		Data: calldata,
	})
	if err != nil || gasLimit == 0 {
		gasLimit = 150000 // Safe default gas limit for anchorRoot
	}
	// Add 20% safety margin to estimated gas limit
	gasLimit = gasLimit * 120 / 100

	feeData, err := w.client.GetFeeData(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch fee data: %w", err)
	}
	if feeData.MaxFeePerGas == nil || feeData.MaxFeePerGas.Sign() < 0 || feeData.MaxFeePerGas.Cmp(maxUint256) > 0 {
		return nil, "", fmt.Errorf("invalid feeData.MaxFeePerGas")
	}
	if feeData.MaxPriorityFeePerGas == nil || feeData.MaxPriorityFeePerGas.Sign() < 0 || feeData.MaxPriorityFeePerGas.Cmp(maxUint256) > 0 {
		return nil, "", fmt.Errorf("invalid feeData.MaxPriorityFeePerGas")
	}
	if feeData.MaxFeePerGas.Cmp(feeData.MaxPriorityFeePerGas) < 0 {
		return nil, "", fmt.Errorf("maxFeePerGas cannot be less than maxPriorityFeePerGas")
	}

	unsignedTx := &blockchain.UnsignedTx{
		ChainID:              big.NewInt(w.cfg.ChainID),
		Nonce:                uint64(reservation.Nonce),
		MaxPriorityFeePerGas: feeData.MaxPriorityFeePerGas,
		MaxFeePerGas:         feeData.MaxFeePerGas,
		GasLimit:             gasLimit,
		To:                   w.cfg.ContractAddress,
		Value:                big.NewInt(0),
		Data:                 calldata,
	}

	signedRawHex, predictedHash, err := w.signer.SignTransaction(unsignedTx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	tx, err := w.repo.CreateBlockchainTransaction(ctx, db.CreateBlockchainTransactionParams{
		BatchID:                 batch.ID,
		NonceReservationID:      reservation.ID,
		ReplacementSequence:     0,
		ChainID:                 w.cfg.ChainID,
		FromAddress:             w.cfg.SignerAddress,
		ToAddress:               w.cfg.ContractAddress,
		Nonce:                   reservation.Nonce,
		TransactionType:         2, // EIP-1559 Type 2
		ValueWei:                bigIntToNumeric(big.NewInt(0)),
		Calldata:                calldata,
		GasLimit:                int64(gasLimit),
		MaxFeePerGasWei:         bigIntToNumeric(feeData.MaxFeePerGas),
		MaxPriorityFeePerGasWei: bigIntToNumeric(feeData.MaxPriorityFeePerGas),
		TxHash:                  predictedHash,
		ReplacesTransactionID:   pgtype.UUID{Valid: false},
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to persist PREPARED transaction: %w", err)
	}

	_ = w.repo.SetAuthoritativeTransaction(ctx, batch.ID, tx.ID)

	return tx, signedRawHex, nil
}

func (w *Worker) pollReceiptAndConfirm(
	ctx context.Context,
	batch *db.MerkleBatch,
	reservation *db.SignerNonceReservation,
	tx *db.BlockchainTransaction,
) error {
	deadline := time.Now().Add(w.cfg.ConfirmationTimeout)
	retryAttempt := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Periodically extend lease while polling
		_ = w.repo.ExtendBatchClaim(ctx, batch.ID, w.cfg.WorkerID, int32(w.cfg.BatchLeaseDuration.Seconds()))

		receipt, err := w.client.GetTransactionReceipt(ctx, tx.TxHash)
		if err == nil && receipt != nil {
			// Receipt obtained! Validate success and event
			rootBytes, _ := hexTo32Bytes(batch.MerkleRoot.String)
			batchIDBytes, _ := hexTo32Bytes(batch.CanonicalBatchID)

			_, valErr := blockchain.ParseAndValidateRootAnchoredEvent(
				receipt,
				w.cfg.ContractAddress,
				rootBytes,
				batchIDBytes,
				w.cfg.SignerAddress,
				uint32(batch.LeafCount),
			)
			if valErr != nil {
				_ = w.repo.MarkTransactionFailed(ctx, tx.ID, "EVENT_VALIDATION_FAILED", "EVENT_MISMATCH")
				_ = w.repo.MarkBatchFailed(ctx, batch.ID, "CONFIRMATION", "EVENT_VALIDATION_FAILED", "INVALID_ROOT_ANCHORED_EVENT")
				return fmt.Errorf("event validation failed: %w", valErr)
			}

			// Check confirmations
			currentHeight, hErr := w.client.GetBlockHeight(ctx)
			if hErr == nil {
				confirmations := int64(0)
				if currentHeight >= receipt.BlockNumber {
					confirmations = int64(currentHeight - receipt.BlockNumber + 1)
				}

				if confirmations >= int64(w.cfg.ConfirmationsRequired) {
					// Verify block hash to detect reorganization
					header, bErr := w.client.GetBlockByNumber(ctx, receipt.BlockNumber)
					if bErr == nil && header != nil && !strings.EqualFold(header.Hash, receipt.BlockHash) {
						_ = w.repo.MarkTransactionFailed(ctx, tx.ID, "REORG_DETECTED", "BLOCK_HASH_MISMATCH")
						_ = w.repo.MarkBatchFailed(ctx, batch.ID, "CONFIRMATION", "REORG_DETECTED", "CANONICAL_CHAIN_REORGANIZED")
						return fmt.Errorf("blockchain reorganization detected at block %d", receipt.BlockNumber)
					}

					// CONFIRMED!
					_ = w.repo.MarkTransactionMined(ctx, tx.ID, int64(receipt.BlockNumber), receipt.BlockHash, int64(receipt.GasUsed))
					_ = w.repo.MarkBatchConfirmed(ctx, batch.ID, int64(receipt.BlockNumber), receipt.BlockHash, int32(confirmations))
					_ = w.repo.CommitNonceReservation(ctx, reservation.ID)

					w.logger.Info("batch successfully anchored and confirmed on-chain",
						"batch_id", UUIDToString(batch.ID),
						"block_number", receipt.BlockNumber,
						"tx_hash", receipt.TxHash,
						"confirmations", confirmations,
					)
					return nil
				}
			}
		}

		if time.Now().After(deadline) {
			// Window expired: check replacement attempt
			if retryAttempt < w.cfg.MaxRetries {
				retryAttempt++
				w.logger.Warn("receipt timeout, attempting EIP-1559 replacement",
					"retry_attempt", retryAttempt,
					"old_tx_hash", tx.TxHash,
				)

				newTx, newSignedRawHex, rErr := w.createReplacementAttempt(ctx, batch, reservation, tx, retryAttempt)
				if rErr != nil {
					w.logger.Error("failed to create replacement transaction", "error", rErr)
				} else {
					tx = newTx
					_, _ = w.client.BroadcastTransaction(ctx, newSignedRawHex)
					_ = w.repo.MarkTransactionBroadcast(ctx, tx.ID)
					deadline = time.Now().Add(w.cfg.ConfirmationTimeout)
					continue
				}
			}

			// Retries exhausted
			_ = w.repo.MarkTransactionFailed(ctx, tx.ID, "RETRIES_EXHAUSTED", "RECEIPT_TIMEOUT")
			_ = w.repo.MarkBatchFailed(ctx, batch.ID, "CONFIRMATION", "RETRIES_EXHAUSTED", "MAX_CONFIRMATION_RETRIES_EXCEEDED")
			_ = w.repo.ReleaseNonceReservation(ctx, reservation.ID)
			return fmt.Errorf("batch confirmation timed out after %d retries", w.cfg.MaxRetries)
		}

		w.sleeper(w.cfg.PollInterval)
	}
}

var maxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

func (w *Worker) createReplacementAttempt(
	ctx context.Context,
	batch *db.MerkleBatch,
	reservation *db.SignerNonceReservation,
	oldTx *db.BlockchainTransaction,
	retrySeq int,
) (*db.BlockchainTransaction, string, error) {
	// Validate old numeric fee fields first
	oldMaxFee, err := numericToBigInt(oldTx.MaxFeePerGasWei)
	if err != nil {
		return nil, "", fmt.Errorf("invalid old max_fee_per_gas_wei: %w", err)
	}
	oldPriorityFee, err := numericToBigInt(oldTx.MaxPriorityFeePerGasWei)
	if err != nil {
		return nil, "", fmt.Errorf("invalid old max_priority_fee_per_gas_wei: %w", err)
	}

	bumpFactor := big.NewInt(int64(100 + w.cfg.FeeBumpPercentage))
	hundred := big.NewInt(100)

	newMaxFee := new(big.Int).Mul(oldMaxFee, bumpFactor)
	newMaxFee.Div(newMaxFee, hundred)

	newPriorityFee := new(big.Int).Mul(oldPriorityFee, bumpFactor)
	newPriorityFee.Div(newPriorityFee, hundred)

	// Ensure replacement fees increase by configured percentage and at least 1 wei
	minMaxFee := new(big.Int).Add(oldMaxFee, big.NewInt(1))
	if newMaxFee.Cmp(minMaxFee) < 0 {
		newMaxFee.Set(minMaxFee)
	}
	minPriorityFee := new(big.Int).Add(oldPriorityFee, big.NewInt(1))
	if newPriorityFee.Cmp(minPriorityFee) < 0 {
		newPriorityFee.Set(minPriorityFee)
	}

	if newMaxFee.Cmp(maxUint256) > 0 || newPriorityFee.Cmp(maxUint256) > 0 {
		return nil, "", fmt.Errorf("bumped replacement fees exceed uint256 max")
	}

	unsignedTx := &blockchain.UnsignedTx{
		ChainID:              big.NewInt(w.cfg.ChainID),
		Nonce:                uint64(reservation.Nonce),
		MaxPriorityFeePerGas: newPriorityFee,
		MaxFeePerGas:         newMaxFee,
		GasLimit:             uint64(oldTx.GasLimit),
		To:                   w.cfg.ContractAddress,
		Value:                big.NewInt(0),
		Data:                 oldTx.Calldata,
	}

	signedRawHex, predictedHash, err := w.signer.SignTransaction(unsignedTx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to sign replacement transaction: %w", err)
	}

	// Mark current attempt REPLACED only after new replacement signed successfully
	_ = w.repo.MarkTransactionReplaced(ctx, oldTx.ID)

	newTx, err := w.repo.CreateBlockchainTransaction(ctx, db.CreateBlockchainTransactionParams{
		BatchID:                 batch.ID,
		NonceReservationID:      reservation.ID,
		ReplacementSequence:     int32(retrySeq),
		ChainID:                 w.cfg.ChainID,
		FromAddress:             w.cfg.SignerAddress,
		ToAddress:               w.cfg.ContractAddress,
		Nonce:                   reservation.Nonce,
		TransactionType:         2,
		ValueWei:                oldTx.ValueWei,
		Calldata:                oldTx.Calldata,
		GasLimit:                oldTx.GasLimit,
		MaxFeePerGasWei:         bigIntToNumeric(newMaxFee),
		MaxPriorityFeePerGasWei: bigIntToNumeric(newPriorityFee),
		TxHash:                  predictedHash,
		ReplacesTransactionID:   oldTx.ID,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to persist replacement transaction: %w", err)
	}

	_ = w.repo.SetAuthoritativeTransaction(ctx, batch.ID, newTx.ID)

	return newTx, signedRawHex, nil
}

func (w *Worker) buildUnsignedTx(
	batch *db.MerkleBatch,
	nonce int64,
	calldata []byte,
	gasLimit int64,
	maxFee pgtype.Numeric,
	maxTip pgtype.Numeric,
) (*blockchain.UnsignedTx, error) {
	if nonce < 0 {
		return nil, fmt.Errorf("nonce cannot be negative: %d", nonce)
	}
	if gasLimit <= 0 {
		return nil, fmt.Errorf("gas limit must be positive: %d", gasLimit)
	}

	maxFeeBI, err := numericToBigInt(maxFee)
	if err != nil {
		return nil, fmt.Errorf("invalid max_fee_per_gas_wei: %w", err)
	}

	maxTipBI, err := numericToBigInt(maxTip)
	if err != nil {
		return nil, fmt.Errorf("invalid max_priority_fee_per_gas_wei: %w", err)
	}

	return &blockchain.UnsignedTx{
		ChainID:              big.NewInt(w.cfg.ChainID),
		Nonce:                uint64(nonce),
		MaxPriorityFeePerGas: maxTipBI,
		MaxFeePerGas:         maxFeeBI,
		GasLimit:             uint64(gasLimit),
		To:                   w.cfg.ContractAddress,
		Value:                big.NewInt(0),
		Data:                 calldata,
	}, nil
}

func hexTo32Bytes(hexStr string) ([32]byte, error) {
	clean := strings.TrimPrefix(strings.TrimSpace(hexStr), "0x")
	bytes, err := hex.DecodeString(clean)
	var out [32]byte
	if err != nil || len(bytes) != 32 {
		return out, fmt.Errorf("invalid 32-byte hex: %s", hexStr)
	}
	copy(out[:], bytes)
	return out, nil
}

func bigIntToNumeric(val *big.Int) pgtype.Numeric {
	if val == nil {
		return pgtype.Numeric{Valid: false}
	}
	var num pgtype.Numeric
	_ = num.Scan(val.String())
	return num
}

func numericToBigInt(num pgtype.Numeric) (*big.Int, error) {
	if !num.Valid {
		return nil, fmt.Errorf("numeric value is invalid or SQL NULL")
	}
	if num.NaN {
		return nil, fmt.Errorf("numeric value is NaN")
	}
	if num.InfinityModifier != pgtype.Finite {
		return nil, fmt.Errorf("numeric value is infinity")
	}
	if num.Int == nil {
		return nil, fmt.Errorf("numeric value Int is nil")
	}
	if num.Int.Sign() < 0 {
		return nil, fmt.Errorf("numeric value cannot be negative: %s", num.Int.String())
	}

	var n *big.Int
	if num.Exp > 0 {
		mul := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(num.Exp)), nil)
		n = new(big.Int).Mul(num.Int, mul)
	} else if num.Exp < 0 {
		divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(-num.Exp)), nil)
		rem := new(big.Int)
		quotient := new(big.Int)
		quotient.QuoRem(num.Int, divisor, rem)
		if rem.Sign() != 0 {
			return nil, fmt.Errorf("numeric value has fractional remainder: %s with exp %d", num.Int.String(), num.Exp)
		}
		n = quotient
	} else {
		n = new(big.Int).Set(num.Int)
	}

	if n.Cmp(maxUint256) > 0 {
		return nil, fmt.Errorf("numeric value exceeds uint256 max: %s", n.String())
	}

	return n, nil
}
