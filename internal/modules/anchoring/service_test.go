package anchoring

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/surekha-software-developer/trustdocsedutoemploybackend/db/sqlc"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/core"
	"github.com/surekha-software-developer/trustdocsedutoemploybackend/internal/crypto/merkle"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func generateTestEligibleCerts(count int) []EligibleCertificate {
	certs := make([]EligibleCertificate, count)
	for i := 0; i < count; i++ {
		publicID := fmt.Sprintf("TD-CERT-%016X", i+1)
		docHashBytes := make([]byte, 32)
		// deterministic docHash
		for j := 0; j < 32; j++ {
			docHashBytes[j] = byte((i*31 + j) % 256)
		}
		docHash := hex.EncodeToString(docHashBytes)

		certs[i] = EligibleCertificate{
			ID:           randomUUID(),
			PublicID:     publicID,
			DocumentHash: pgtype.Text{String: docHash, Valid: true},
			Status:       "ISSUED",
		}
	}
	return certs
}

func TestService_DeterministicBatchingAndLeafCounts(t *testing.T) {
	leafCounts := []int{1, 2, 3, 5, 16, 100}
	ctx := context.Background()

	for _, count := range leafCounts {
		t.Run(fmt.Sprintf("LeafCount_%d", count), func(t *testing.T) {
			repo := NewMockRepository()
			certs := generateTestEligibleCerts(count)
			for _, c := range certs {
				repo.AddEligibleCertificate(c)
			}

			svc := NewService(repo, int32(count), newTestLogger())
			resp, err := svc.CreateBatch(ctx, int32(count))
			if err != nil {
				t.Fatalf("failed to create batch for count %d: %v", count, err)
			}

			if resp.LeafCount != int32(count) {
				t.Errorf("expected leaf count %d, got %d", count, resp.LeafCount)
			}
			if resp.Status != "READY" {
				t.Errorf("expected batch status READY, got %s", resp.Status)
			}
			if resp.MerkleRoot == nil || !strings.HasPrefix(*resp.MerkleRoot, "0x") {
				t.Fatalf("invalid merkle root: %v", resp.MerkleRoot)
			}

			// Verify proof for every single certificate in the batch
			for _, cert := range certs {
				proofData, err := svc.GetBatchProofForCertificate(ctx, cert.PublicID)
				if err != nil {
					t.Fatalf("failed to get proof for cert %s: %v", cert.PublicID, err)
				}

				leafBytes, _, err := merkle.DeriveLeafHash(cert.PublicID, cert.DocumentHash.String)
				if err != nil {
					t.Fatalf("failed to compute leaf hash: %v", err)
				}

				rootBytes, err := merkle.ParseHex32(*resp.MerkleRoot)
				if err != nil {
					t.Fatalf("failed to parse root hex: %v", err)
				}

				proofBytes := make([][32]byte, len(proofData.Proof))
				for pi, ps := range proofData.Proof {
					pNode, err := merkle.ParseHex32(ps)
					if err != nil {
						t.Fatalf("failed to parse proof node: %v", err)
					}
					proofBytes[pi] = pNode
				}

				valid, err := merkle.VerifyProof(rootBytes, leafBytes, proofBytes)
				if err != nil {
					t.Fatalf("VerifyProof error: %v", err)
				}
				if !valid {
					t.Errorf("proof failed to verify for cert %s in tree of size %d", cert.PublicID, count)
				}
			}
		})
	}
}

func TestService_CanonicalBatchIDDerivation(t *testing.T) {
	// Fixed authoritative vector test
	fixedUUIDStr := "10000000-0000-0000-0000-000000000001"
	expectedCanonicalID := "0x28e964c4317248325efd848a3777a1f7d73bce53b17f9acb5b139036a3eda343"

	// 1. String UUID derivation
	derivedFromStr, err := merkle.DeriveCanonicalBatchID(fixedUUIDStr)
	if err != nil {
		t.Fatalf("DeriveCanonicalBatchID(%q) error: %v", fixedUUIDStr, err)
	}
	if derivedFromStr != expectedCanonicalID {
		t.Errorf("DeriveCanonicalBatchID mismatch: expected %s, got %s", expectedCanonicalID, derivedFromStr)
	}

	// 2. Raw 16 bytes derivation
	var rawUUID [16]byte
	rawUUID[0] = 0x10
	rawUUID[15] = 0x01
	derivedFromBytes := merkle.DeriveCanonicalBatchIDFromBytes(rawUUID)
	if derivedFromBytes != expectedCanonicalID {
		t.Errorf("DeriveCanonicalBatchIDFromBytes mismatch: expected %s, got %s", expectedCanonicalID, derivedFromBytes)
	}

	// 3. Service batch creation integration
	repo := NewMockRepository()
	certs := generateTestEligibleCerts(2)
	for _, c := range certs {
		repo.AddEligibleCertificate(c)
	}

	svc := NewService(repo, 10, newTestLogger())
	resp, err := svc.CreateBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("failed to create batch: %v", err)
	}

	if !strings.HasPrefix(resp.CanonicalBatchID, "0x") || len(resp.CanonicalBatchID) != 66 {
		t.Errorf("invalid canonical batch ID: %s", resp.CanonicalBatchID)
	}
}

func TestService_ImmutableSnapshotPersistence(t *testing.T) {
	repo := NewMockRepository()
	certs := generateTestEligibleCerts(3)
	for _, c := range certs {
		repo.AddEligibleCertificate(c)
	}

	svc := NewService(repo, 10, newTestLogger())
	resp, err := svc.CreateBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("failed to create batch: %v", err)
	}

	batchUUID := StringToUUID(resp.ID)
	batchInDB, err := repo.GetBatchByID(context.Background(), batchUUID)
	if err != nil {
		t.Fatalf("batch not found in repo: %v", err)
	}
	if batchInDB.Status != "READY" {
		t.Errorf("expected status READY, got %s", batchInDB.Status)
	}
	if batchInDB.LeafCount != 3 {
		t.Errorf("expected leaf count 3, got %d", batchInDB.LeafCount)
	}
}

func TestService_VerifyProof_MathematicallyValidAndAnchorConfirmed(t *testing.T) {
	repo := NewMockRepository()
	certs := generateTestEligibleCerts(3)
	for _, c := range certs {
		repo.AddEligibleCertificate(c)
	}

	svc := NewService(repo, 10, newTestLogger())
	batchResp, err := svc.CreateBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("failed to create batch: %v", err)
	}

	batchUUID := StringToUUID(batchResp.ID)

	// Simulate batch confirmed with authoritative tx
	resID := randomUUID()
	txID := randomUUID()
	repo.transactions[UUIDToString(txID)] = &db.BlockchainTransaction{
		ID:      txID,
		BatchID: batchUUID,
		TxHash:  "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Status:  "MINED",
	}
	b := repo.batches[UUIDToString(batchUUID)]
	b.Status = "CONFIRMED"
	b.AuthoritativeTransactionID = txID
	b.ChainID = pgtype.Int8{Int64: 80002, Valid: true}
	b.ContractAddress = pgtype.Text{String: "0x5FbDB2315678afecb367f032d93F642f64180aa3", Valid: true}
	b.BlockNumber = pgtype.Int8{Int64: 12345, Valid: true}
	b.BlockHash = pgtype.Text{String: "0xblockhash12345", Valid: true}
	b.ConfirmedAt = pgtype.Timestamptz{Time: b.CreatedAt.Time, Valid: true}
	_ = resID

	targetCert := certs[0]
	proofData, err := svc.GetBatchProofForCertificate(context.Background(), targetCert.PublicID)
	if err != nil {
		t.Fatalf("failed to retrieve proof: %v", err)
	}

	verifyResp, err := svc.VerifyProof(context.Background(), VerifyProofRequest{
		PublicID:     targetCert.PublicID,
		DocumentHash: targetCert.DocumentHash.String,
		MerkleRoot:   *batchResp.MerkleRoot,
		Proof:        proofData.Proof,
	})
	if err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}

	if !verifyResp.MathematicalProofValid {
		t.Errorf("expected mathematical_proof_valid = true")
	}
	if !verifyResp.AnchorConfirmed {
		t.Errorf("expected anchor_confirmed = true")
	}
	if verifyResp.TxHash == nil || *verifyResp.TxHash != "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" {
		t.Errorf("unexpected tx hash: %v", verifyResp.TxHash)
	}
	if verifyResp.BlockNumber == nil || *verifyResp.BlockNumber != 12345 {
		t.Errorf("unexpected block number: %v", verifyResp.BlockNumber)
	}
}

func TestService_VerifyProof_ValidProofUnconfirmed(t *testing.T) {
	repo := NewMockRepository()
	certs := generateTestEligibleCerts(3)
	for _, c := range certs {
		repo.AddEligibleCertificate(c)
	}

	svc := NewService(repo, 10, newTestLogger())
	batchResp, err := svc.CreateBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("failed to create batch: %v", err)
	}

	// Batch is still in status READY (not yet CONFIRMED on chain)
	targetCert := certs[0]
	proofData, err := svc.GetBatchProofForCertificate(context.Background(), targetCert.PublicID)
	if err != nil {
		t.Fatalf("failed to retrieve proof: %v", err)
	}

	verifyResp, err := svc.VerifyProof(context.Background(), VerifyProofRequest{
		PublicID:     targetCert.PublicID,
		DocumentHash: targetCert.DocumentHash.String,
		MerkleRoot:   *batchResp.MerkleRoot,
		Proof:        proofData.Proof,
	})
	if err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}

	if !verifyResp.MathematicalProofValid {
		t.Errorf("expected mathematical_proof_valid = true")
	}
	if verifyResp.AnchorConfirmed {
		t.Errorf("expected anchor_confirmed = false for unconfirmed batch")
	}
}

func TestService_VerifyProof_MathematicallyInvalid(t *testing.T) {
	repo := NewMockRepository()
	certs := generateTestEligibleCerts(2)
	for _, c := range certs {
		repo.AddEligibleCertificate(c)
	}

	svc := NewService(repo, 10, newTestLogger())
	batchResp, err := svc.CreateBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("failed to create batch: %v", err)
	}

	targetCert := certs[0]
	proofData, err := svc.GetBatchProofForCertificate(context.Background(), targetCert.PublicID)
	if err != nil {
		t.Fatalf("failed to retrieve proof: %v", err)
	}

	// Corrupt one sibling
	corruptedProof := make([]string, len(proofData.Proof))
	copy(corruptedProof, proofData.Proof)
	if len(corruptedProof) > 0 {
		corruptedProof[0] = "0x0000000000000000000000000000000000000000000000000000000000000000"
	}

	verifyResp, err := svc.VerifyProof(context.Background(), VerifyProofRequest{
		PublicID:     targetCert.PublicID,
		DocumentHash: targetCert.DocumentHash.String,
		MerkleRoot:   *batchResp.MerkleRoot,
		Proof:        corruptedProof,
	})
	if err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}

	if verifyResp.MathematicalProofValid {
		t.Errorf("expected mathematical_proof_valid = false for corrupted proof")
	}
	if verifyResp.AnchorConfirmed {
		t.Errorf("expected anchor_confirmed = false for invalid proof")
	}
}

func TestService_VerifyProof_RevokedOrReplacedHistoricalProofSemantics(t *testing.T) {
	repo := NewMockRepository()
	certs := generateTestEligibleCerts(2)
	for _, c := range certs {
		repo.AddEligibleCertificate(c)
	}

	svc := NewService(repo, 10, newTestLogger())
	batchResp, err := svc.CreateBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("failed to create batch: %v", err)
	}

	// Certificate was later REVOKED in the database
	repo.certificates[certs[0].PublicID].Status = "REVOKED"

	proofData, _ := svc.GetBatchProofForCertificate(context.Background(), certs[0].PublicID)

	verifyResp, err := svc.VerifyProof(context.Background(), VerifyProofRequest{
		PublicID:     certs[0].PublicID,
		DocumentHash: certs[0].DocumentHash.String,
		MerkleRoot:   *batchResp.MerkleRoot,
		Proof:        proofData.Proof,
	})
	if err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}

	// Proof is mathematically valid (existence anchored), but certificate status is explicitly REVOKED
	if !verifyResp.MathematicalProofValid {
		t.Errorf("expected mathematical proof to remain valid historically")
	}
	if verifyResp.CertificateStatus == nil || *verifyResp.CertificateStatus != "REVOKED" {
		t.Errorf("expected CertificateStatus 'REVOKED', got %v", verifyResp.CertificateStatus)
	}
}

func TestService_VerifyProof_MalformedInputs(t *testing.T) {
	svc := NewService(NewMockRepository(), 10, newTestLogger())
	ctx := context.Background()

	validRoot := "0x" + strings.Repeat("a", 64)
	validHash := strings.Repeat("b", 64)
	validProof := []string{"0x" + strings.Repeat("c", 64)}

	// 1. Bad public ID
	_, err := svc.VerifyProof(ctx, VerifyProofRequest{
		PublicID:     "invalid-id",
		DocumentHash: validHash,
		MerkleRoot:   validRoot,
		Proof:        validProof,
	})
	if err == nil || !strings.Contains(err.Error(), "public_id") {
		t.Errorf("expected error for malformed public ID, got %v", err)
	}

	// 2. Bad document hash (not 64 hex)
	_, err = svc.VerifyProof(ctx, VerifyProofRequest{
		PublicID:     "TD-CERT-A1B2C3D4E5F60718",
		DocumentHash: "short",
		MerkleRoot:   validRoot,
		Proof:        validProof,
	})
	if err == nil || !strings.Contains(err.Error(), "document_hash") {
		t.Errorf("expected error for malformed document hash, got %v", err)
	}

	// 3. Bad Merkle root (missing 0x prefix)
	_, err = svc.VerifyProof(ctx, VerifyProofRequest{
		PublicID:     "TD-CERT-A1B2C3D4E5F60718",
		DocumentHash: validHash,
		MerkleRoot:   strings.Repeat("a", 64),
		Proof:        validProof,
	})
	if err == nil || !strings.Contains(err.Error(), "merkle_root") {
		t.Errorf("expected error for missing 0x on merkle root, got %v", err)
	}

	// 4. Bad proof sibling (non-hex)
	_, err = svc.VerifyProof(ctx, VerifyProofRequest{
		PublicID:     "TD-CERT-A1B2C3D4E5F60718",
		DocumentHash: validHash,
		MerkleRoot:   validRoot,
		Proof:        []string{"not-a-hex-hash"},
	})
	if err == nil || !strings.Contains(err.Error(), "sibling") {
		t.Errorf("expected error for invalid sibling hex, got %v", err)
	}
}

func TestService_VerifyProof_ProofDepthLimit(t *testing.T) {
	svc := NewService(NewMockRepository(), 10, newTestLogger())
	ctx := context.Background()

	// Create proof with 21 siblings (max is 20)
	deepProof := make([]string, 21)
	for i := range deepProof {
		deepProof[i] = "0x" + strings.Repeat("0", 64)
	}

	_, err := svc.VerifyProof(ctx, VerifyProofRequest{
		PublicID:     "TD-CERT-A1B2C3D4E5F60718",
		DocumentHash: strings.Repeat("a", 64),
		MerkleRoot:   "0x" + strings.Repeat("b", 64),
		Proof:        deepProof,
	})

	var appErr *core.AppError
	if err == nil {
		t.Fatalf("expected error for depth limit exceeded")
	}
	appErr, _ = err.(*core.AppError)
	if appErr == nil || appErr.Code != core.ErrCodeProofDepthExceeded {
		t.Errorf("expected ErrCodeProofDepthExceeded, got %v", err)
	}
}

func TestService_VerifyProof_PIIExclusion(t *testing.T) {
	resp := VerifyProofResponse{
		MathematicalProofValid: true,
		AnchorConfirmed:        true,
		PublicID:               "TD-CERT-A1B2C3D4E5F60718",
		MerkleRoot:             "0x" + strings.Repeat("a", 64),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	jsonStr := string(data)
	prohibitedKeywords := []string{
		"recipient_name",
		"recipient_email",
		"student_id",
		"storage_key",
		"file_name",
		"private_key",
		"signer_key",
		"internal_id",
	}

	for _, kw := range prohibitedKeywords {
		if strings.Contains(jsonStr, kw) {
			t.Errorf("VerifyProofResponse JSON leaked sensitive attribute: %s", kw)
		}
	}
}

func TestService_CreateBatch_EmptyCertificates(t *testing.T) {
	svc := NewService(NewMockRepository(), 10, newTestLogger())
	_, err := svc.CreateBatch(context.Background(), 10)

	var appErr *core.AppError
	if err == nil {
		t.Fatalf("expected error when no eligible certificates exist")
	}
	appErr, _ = err.(*core.AppError)
	if appErr == nil || appErr.Code != core.ErrCodeBatchEmpty {
		t.Errorf("expected ErrCodeBatchEmpty, got %v", err)
	}
}
