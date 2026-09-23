package anchoring

// VerifyProofRequest defines the payload for POST /api/v1/public/certificates/verify-proof.
// Accepts only canonical public verification attributes; never trusts caller-provided leaf hashes.
type VerifyProofRequest struct {
	PublicID     string   `json:"public_id" binding:"required"`
	DocumentHash string   `json:"document_hash" binding:"required"`
	MerkleRoot   string   `json:"merkle_root" binding:"required"`
	Proof        []string `json:"proof" binding:"required"`
}

// CreateBatchRequest defines options for triggering manual batch creation.
type CreateBatchRequest struct {
	BatchSize int32 `json:"batch_size"`
}
