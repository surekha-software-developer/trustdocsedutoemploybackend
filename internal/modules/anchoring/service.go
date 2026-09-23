package anchoring

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/crypto/merkle"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/modules/certificates"
)

var (
	publicIDRegex = regexp.MustCompile(`^TD-CERT-[A-Z0-9]{16,32}$`)
	hex64Regex    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rootHexRegex  = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
)

func bytes32ToHex(b [32]byte) string {
	return "0x" + hex.EncodeToString(b[:])
}

func proofBytesToHexSlice(proof [][32]byte) []string {
	out := make([]string, len(proof))
	for i, node := range proof {
		out[i] = "0x" + hex.EncodeToString(node[:])
	}
	return out
}

// CertificateProofData contains the Merkle proof and anchor metadata for a certificate.
type CertificateProofData struct {
	IsAnchored       bool     `json:"is_anchored"`
	MerkleRoot       *string  `json:"merkle_root,omitempty"`
	CanonicalBatchID *string  `json:"canonical_batch_id,omitempty"`
	ChainID          *int64   `json:"chain_id,omitempty"`
	ContractAddress  *string  `json:"contract_address,omitempty"`
	TxHash           *string  `json:"tx_hash,omitempty"`
	BlockNumber      *int64   `json:"block_number,omitempty"`
	BlockHash        *string  `json:"block_hash,omitempty"`
	ConfirmedAt      *string  `json:"confirmed_at,omitempty"`
	Proof            []string `json:"proof,omitempty"`
	LeafIndex        *int32   `json:"leaf_index,omitempty"`
}

// Service coordinates Merkle batching, proof verification, and administrative batch inspection.
type Service struct {
	repo           Repository
	defaultBatchSz int32
	logger         *slog.Logger
}

// NewService constructs an anchoring Service.
func NewService(repo Repository, defaultBatchSize int32, logger *slog.Logger) *Service {
	if defaultBatchSize <= 0 {
		defaultBatchSize = 100
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		repo:           repo,
		defaultBatchSz: defaultBatchSize,
		logger:         logger,
	}
}

// CreateBatch aggregates eligible ISSUED certificates and creates a READY Merkle batch.
func (s *Service) CreateBatch(ctx context.Context, batchSize int32) (*BatchResponse, error) {
	if batchSize <= 0 {
		batchSize = s.defaultBatchSz
	}

	eligible, err := s.repo.FindEligibleCertificates(ctx, batchSize)
	if err != nil {
		s.logger.Error("failed to query eligible certificates for batch", "error", err)
		return nil, core.NewAppError(core.ErrCodeInternal, "Failed to retrieve certificates for batching")
	}

	if len(eligible) == 0 {
		return nil, core.NewAppError(core.ErrCodeBatchEmpty, "No eligible certificates available for batching")
	}

	// Generate 16 cryptographically secure random bytes for the batch UUID
	var rawUUID [16]byte
	if _, err := rand.Read(rawUUID[:]); err != nil {
		return nil, core.NewAppError(core.ErrCodeInternal, "Failed to generate batch entropy")
	}

	canonicalBatchID := merkle.DeriveCanonicalBatchIDFromBytes(rawUUID)

	// Validate inputs and construct leaf inputs
	inputs := make([]merkle.CertificateLeafInput, len(eligible))
	for i, cert := range eligible {
		if !publicIDRegex.MatchString(cert.PublicID) {
			return nil, core.NewAppError(core.ErrCodeBadRequest, fmt.Sprintf("Certificate %s has invalid public_id format", cert.PublicID))
		}
		if !cert.DocumentHash.Valid || !hex64Regex.MatchString(cert.DocumentHash.String) {
			return nil, core.NewAppError(core.ErrCodeBadRequest, fmt.Sprintf("Certificate %s has invalid document_hash format", cert.PublicID))
		}

		inputs[i] = merkle.CertificateLeafInput{
			CertificateID: UUIDToString(cert.ID),
			PublicID:      cert.PublicID,
			DocumentHash:  cert.DocumentHash.String,
		}
	}

	// Build Merkle tree using the approved TD-MERKLE-KECCAK256-V1 algorithm
	tree, err := merkle.BuildTree(inputs)
	if err != nil {
		s.logger.Error("failed to build merkle tree", "error", err)
		return nil, core.NewAppError(core.ErrCodeInternal, "Failed to construct Merkle tree")
	}

	// Prepare leaf data and normalized proof nodes using strict conversions
	leafDataList := make([]LeafData, len(tree.Leaves))
	for i, leaf := range tree.Leaves {
		leafDataList[i] = LeafData{
			CertificateID: StringToUUID(leaf.CertificateID),
			PublicID:      leaf.PublicID,
			DocumentHash:  leaf.DocumentHash,
			LeafIndex:     int32(leaf.LeafIndex),
			LeafHash:      bytes32ToHex(leaf.LeafHash),
			ProofDepth:    int32(len(leaf.Proof)),
			ProofNodes:    proofBytesToHexSlice(leaf.Proof),
		}
	}

	// Persist batch, snapshots, proof nodes, and finalize BUILDING -> READY atomically
	batch, err := s.repo.CreateBatchWithCertificates(
		ctx,
		canonicalBatchID,
		merkle.AlgorithmTDKeccak256V1,
		merkle.TreeVersion1,
		merkle.LeafEncodingTDLeafV1,
		merkle.ProofFormatTDSortedV1,
		leafDataList,
		bytes32ToHex(tree.Root),
	)
	if err != nil {
		s.logger.Error("failed to persist merkle batch", "error", err)
		return nil, core.NewAppError(core.ErrCodeInternal, "Failed to persist Merkle batch")
	}

	resp := mapBatchToResponse(batch)
	return &resp, nil
}

// VerifyProof verifies a client-provided Merkle proof against server-side recomputed leaf and stored anchor.
func (s *Service) VerifyProof(ctx context.Context, req VerifyProofRequest) (*VerifyProofResponse, error) {
	// 1. Strict format validation according to HTTP contract (no silent trimming or lowercasing)
	if !publicIDRegex.MatchString(req.PublicID) {
		return nil, core.NewAppError(core.ErrCodeBadRequest, "Invalid public_id format: must match TD-CERT-[A-Z0-9]{16,32}")
	}
	if !hex64Regex.MatchString(req.DocumentHash) {
		return nil, core.NewAppError(core.ErrCodeBadRequest, "Invalid document_hash format: must be 64 lowercase hex characters")
	}
	if !rootHexRegex.MatchString(req.MerkleRoot) {
		return nil, core.NewAppError(core.ErrCodeBadRequest, "Invalid merkle_root format: must be 0x-prefixed 64 lowercase hex characters")
	}
	if len(req.Proof) > merkle.MaxProofDepth {
		return nil, core.NewAppError(core.ErrCodeProofDepthExceeded, fmt.Sprintf("Proof depth %d exceeds maximum limit of %d", len(req.Proof), merkle.MaxProofDepth))
	}
	for idx, sibling := range req.Proof {
		if !rootHexRegex.MatchString(sibling) {
			return nil, core.NewAppError(core.ErrCodeBadRequest, fmt.Sprintf("Proof sibling at index %d has invalid format: must be 0x-prefixed 64 lowercase hex characters", idx))
		}
	}

	// 2. Reuse authoritative Merkle package parser for Merkle root and proof siblings
	rootBytes, err := merkle.ParseHex32(req.MerkleRoot)
	if err != nil {
		return nil, core.NewAppError(core.ErrCodeBadRequest, fmt.Sprintf("Invalid merkle_root format: %v", err))
	}

	proofBytes := make([][32]byte, len(req.Proof))
	for i, sib := range req.Proof {
		node, err := merkle.ParseHex32(sib)
		if err != nil {
			return nil, core.NewAppError(core.ErrCodeBadRequest, fmt.Sprintf("Proof sibling at index %d has invalid format: %v", i, err))
		}
		proofBytes[i] = node
	}

	// 3. Server-side leaf recomputation using authoritative DeriveLeafHash
	leafBytes, _, err := merkle.DeriveLeafHash(req.PublicID, req.DocumentHash)
	if err != nil {
		return nil, core.NewAppError(core.ErrCodeBadRequest, fmt.Sprintf("Failed to compute leaf hash: %v", err))
	}

	// 4. Mathematical proof verification using authoritative VerifyProof
	mathValid, err := merkle.VerifyProof(rootBytes, leafBytes, proofBytes)
	if err != nil {
		s.logger.Warn("merkle proof verification error", "error", err, "public_id", req.PublicID)
		if strings.Contains(err.Error(), "proof depth") {
			return nil, core.NewAppError(core.ErrCodeProofDepthExceeded, fmt.Sprintf("Proof depth exceeds maximum limit of %d", merkle.MaxProofDepth))
		}
		return nil, core.NewAppError(core.ErrCodeInternal, "Failed to verify Merkle proof")
	}

	resp := &VerifyProofResponse{
		MathematicalProofValid: mathValid,
		AnchorConfirmed:        false,
		PublicID:               req.PublicID,
		MerkleRoot:             req.MerkleRoot,
	}

	// 5. Retrieve certificate current status from database
	certRow, err := s.repo.GetCertificateByPublicID(ctx, req.PublicID)
	if err == nil && certRow != nil {
		resp.CertificateStatus = &certRow.Status
	}

	// 6. Query batch certificate and check on-chain confirmation
	// anchor_confirmed must remain false unless mathematical_proof_valid is true
	if mathValid {
		bc, err := s.repo.GetBatchCertificateByPublicID(ctx, req.PublicID)
		if err == nil && bc != nil {
			batch, err := s.repo.GetBatchByID(ctx, bc.BatchID)
			if err == nil && batch != nil {
				// Anchor is confirmed ONLY if batch status is CONFIRMED and Merkle root matches
				if batch.Status == "CONFIRMED" && strings.EqualFold(batch.MerkleRoot.String, req.MerkleRoot) {
					tx, err := s.repo.GetAuthoritativeTransactionForBatch(ctx, batch.ID)
					if err == nil && tx != nil && tx.Status == "MINED" {
						resp.AnchorConfirmed = true
						resp.CanonicalBatchID = &batch.CanonicalBatchID
						if batch.ChainID.Valid {
							cID := batch.ChainID.Int64
							resp.ChainID = &cID
						}
						if batch.ContractAddress.Valid {
							cAddr := batch.ContractAddress.String
							resp.ContractAddress = &cAddr
						}
						if tx.TxHash != "" {
							txH := tx.TxHash
							resp.TxHash = &txH
						}
						if batch.BlockNumber.Valid {
							bNum := batch.BlockNumber.Int64
							resp.BlockNumber = &bNum
						}
						if batch.BlockHash.Valid {
							bHash := batch.BlockHash.String
							resp.BlockHash = &bHash
						}
						if batch.ConfirmedAt.Valid {
							confAt := batch.ConfirmedAt.Time.UTC().Format(time.RFC3339)
							resp.ConfirmedAt = &confAt
						}
						leafIdx := bc.LeafIndex
						resp.LeafIndex = &leafIdx
					}
				}
			}
		}
	}

	return resp, nil
}

// GetBatch retrieves a Merkle batch by UUID string or batch number.
func (s *Service) GetBatch(ctx context.Context, idStr string) (*BatchResponse, error) {
	idStr = strings.TrimSpace(idStr)
	uuid := StringToUUID(idStr)
	if !uuid.Valid {
		return nil, core.NewAppError(core.ErrCodeBadRequest, "Invalid batch UUID format")
	}

	batch, err := s.repo.GetBatchByID(ctx, uuid)
	if err != nil {
		return nil, core.NewAppError(core.ErrCodeBatchNotFound, "Batch not found")
	}

	resp := mapBatchToResponse(batch)
	return &resp, nil
}

// ListBatches lists Merkle batches with pagination.
func (s *Service) ListBatches(ctx context.Context, limit, offset int32) (*BatchListResponse, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	batches, err := s.repo.ListBatches(ctx, limit, offset)
	if err != nil {
		return nil, core.NewAppError(core.ErrCodeInternal, "Failed to list batches")
	}

	total, err := s.repo.CountBatches(ctx)
	if err != nil {
		return nil, core.NewAppError(core.ErrCodeInternal, "Failed to count batches")
	}

	items := make([]BatchResponse, len(batches))
	for i := range batches {
		items[i] = mapBatchToResponse(&batches[i])
	}

	return &BatchListResponse{
		Batches: items,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
	}, nil
}

// GetBatchProofForCertificate retrieves the Merkle proof and anchor metadata for a certificate.
func (s *Service) GetBatchProofForCertificate(ctx context.Context, publicID string) (*CertificateProofData, error) {
	bc, err := s.repo.GetBatchCertificateByPublicID(ctx, publicID)
	if err != nil || bc == nil {
		return &CertificateProofData{IsAnchored: false}, nil
	}

	batch, err := s.repo.GetBatchByID(ctx, bc.BatchID)
	if err != nil || batch == nil {
		return &CertificateProofData{IsAnchored: false}, nil
	}

	proofRows, err := s.repo.GetProofNodesByBatchCertID(ctx, bc.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve proof nodes: %w", err)
	}

	proof := make([]string, len(proofRows))
	for i, p := range proofRows {
		proof[i] = p.SiblingHash
	}

	data := &CertificateProofData{
		IsAnchored: batch.Status == "CONFIRMED",
		Proof:      proof,
		LeafIndex:  &bc.LeafIndex,
	}

	if batch.MerkleRoot.Valid {
		data.MerkleRoot = &batch.MerkleRoot.String
	}
	data.CanonicalBatchID = &batch.CanonicalBatchID

	if batch.ChainID.Valid {
		cID := batch.ChainID.Int64
		data.ChainID = &cID
	}
	if batch.ContractAddress.Valid {
		cAddr := batch.ContractAddress.String
		data.ContractAddress = &cAddr
	}
	if batch.BlockNumber.Valid {
		bNum := batch.BlockNumber.Int64
		data.BlockNumber = &bNum
	}
	if batch.BlockHash.Valid {
		bHash := batch.BlockHash.String
		data.BlockHash = &bHash
	}
	if batch.ConfirmedAt.Valid {
		confAt := batch.ConfirmedAt.Time.UTC().Format(time.RFC3339)
		data.ConfirmedAt = &confAt
	}

	if batch.AuthoritativeTransactionID.Valid {
		tx, err := s.repo.GetAuthoritativeTransactionForBatch(ctx, batch.ID)
		if err == nil && tx != nil && tx.TxHash != "" {
			data.TxHash = &tx.TxHash
		}
	}

	return data, nil
}

// GetCertificateAnchoring adapts GetBatchProofForCertificate into certificates.CertificateAnchoringMetadata.
func (s *Service) GetCertificateAnchoring(ctx context.Context, publicID string) (*certificates.CertificateAnchoringMetadata, error) {
	data, err := s.GetBatchProofForCertificate(ctx, publicID)
	if err != nil || data == nil {
		return nil, err
	}
	return &certificates.CertificateAnchoringMetadata{
		IsAnchored:       data.IsAnchored,
		MerkleRoot:       data.MerkleRoot,
		CanonicalBatchID: data.CanonicalBatchID,
		ChainID:          data.ChainID,
		ContractAddress:  data.ContractAddress,
		TxHash:           data.TxHash,
		BlockNumber:      data.BlockNumber,
		BlockHash:        data.BlockHash,
		ConfirmedAt:      data.ConfirmedAt,
		Proof:            data.Proof,
		LeafIndex:        data.LeafIndex,
	}, nil
}

func mapBatchToResponse(b *db.MerkleBatch) BatchResponse {
	resp := BatchResponse{
		ID:                  UUIDToString(b.ID),
		BatchNumber:         b.BatchNumber,
		CanonicalBatchID:    b.CanonicalBatchID,
		Status:              b.Status,
		TreeAlgorithm:       b.TreeAlgorithm,
		TreeVersion:         b.TreeVersion,
		LeafEncodingVersion: b.LeafEncodingVersion,
		ProofFormatVersion:  b.ProofFormatVersion,
		LeafCount:           b.LeafCount,
		ConfirmationCount:   b.ConfirmationCount,
		RetryCount:          b.RetryCount,
		CreatedAt:           b.CreatedAt.Time.UTC().Format(time.RFC3339),
	}

	if b.MerkleRoot.Valid {
		resp.MerkleRoot = &b.MerkleRoot.String
	}
	if b.AuthoritativeTransactionID.Valid {
		authTxID := UUIDToString(b.AuthoritativeTransactionID)
		resp.AuthoritativeTxID = &authTxID
	}
	if b.ChainID.Valid {
		cID := b.ChainID.Int64
		resp.ChainID = &cID
	}
	if b.ContractAddress.Valid {
		cAddr := b.ContractAddress.String
		resp.ContractAddress = &cAddr
	}
	if b.BlockNumber.Valid {
		bNum := b.BlockNumber.Int64
		resp.BlockNumber = &bNum
	}
	if b.BlockHash.Valid {
		bHash := b.BlockHash.String
		resp.BlockHash = &bHash
	}
	if b.ReadyAt.Valid {
		ra := b.ReadyAt.Time.UTC().Format(time.RFC3339)
		resp.ReadyAt = &ra
	}
	if b.SubmittedAt.Valid {
		sa := b.SubmittedAt.Time.UTC().Format(time.RFC3339)
		resp.SubmittedAt = &sa
	}
	if b.ConfirmedAt.Valid {
		ca := b.ConfirmedAt.Time.UTC().Format(time.RFC3339)
		resp.ConfirmedAt = &ca
	}
	if b.FailedAt.Valid {
		fa := b.FailedAt.Time.UTC().Format(time.RFC3339)
		resp.FailedAt = &fa
	}
	if b.FailureStage.Valid {
		resp.FailureStage = &b.FailureStage.String
	}
	if b.FailureCode.Valid {
		resp.FailureCode = &b.FailureCode.String
	}
	if b.FailureDetailCode.Valid {
		resp.FailureDetailCode = &b.FailureDetailCode.String
	}

	return resp
}
