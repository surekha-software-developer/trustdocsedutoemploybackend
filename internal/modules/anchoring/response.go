package anchoring

// VerifyProofResponse is the public proof verification response.
// Strictly excludes student PII, secrets, internal IDs, and raw signature payloads.
type VerifyProofResponse struct {
	MathematicalProofValid bool    `json:"mathematical_proof_valid"`
	AnchorConfirmed        bool    `json:"anchor_confirmed"`
	CertificateStatus      *string `json:"certificate_status,omitempty"`
	PublicID               string  `json:"public_id"`
	MerkleRoot             string  `json:"merkle_root"`
	CanonicalBatchID       *string `json:"canonical_batch_id,omitempty"`
	ChainID                *int64  `json:"chain_id,omitempty"`
	ContractAddress        *string `json:"contract_address,omitempty"`
	TxHash                 *string `json:"tx_hash,omitempty"`
	BlockNumber            *int64  `json:"block_number,omitempty"`
	BlockHash              *string `json:"block_hash,omitempty"`
	ConfirmedAt            *string `json:"confirmed_at,omitempty"`
	LeafIndex              *int32  `json:"leaf_index,omitempty"`
}

// BatchResponse represents Merkle batch details for administrative review.
type BatchResponse struct {
	ID                  string  `json:"id"`
	BatchNumber         int64   `json:"batch_number"`
	CanonicalBatchID    string  `json:"canonical_batch_id"`
	Status              string  `json:"status"`
	TreeAlgorithm       string  `json:"tree_algorithm"`
	TreeVersion         int32   `json:"tree_version"`
	LeafEncodingVersion string  `json:"leaf_encoding_version"`
	ProofFormatVersion  string  `json:"proof_format_version"`
	MerkleRoot          *string `json:"merkle_root,omitempty"`
	LeafCount           int32   `json:"leaf_count"`
	AuthoritativeTxID   *string `json:"authoritative_tx_id,omitempty"`
	ChainID             *int64  `json:"chain_id,omitempty"`
	ContractAddress     *string `json:"contract_address,omitempty"`
	BlockNumber         *int64  `json:"block_number,omitempty"`
	BlockHash           *string `json:"block_hash,omitempty"`
	ConfirmationCount   int32   `json:"confirmation_count"`
	RetryCount          int32   `json:"retry_count"`
	FailureStage        *string `json:"failure_stage,omitempty"`
	FailureCode         *string `json:"failure_code,omitempty"`
	FailureDetailCode   *string `json:"failure_detail_code,omitempty"`
	CreatedAt           string  `json:"created_at"`
	ReadyAt             *string `json:"ready_at,omitempty"`
	SubmittedAt         *string `json:"submitted_at,omitempty"`
	ConfirmedAt         *string `json:"confirmed_at,omitempty"`
	FailedAt            *string `json:"failed_at,omitempty"`
}

// BatchListResponse represents a paginated list of Merkle batches.
type BatchListResponse struct {
	Batches []BatchResponse `json:"batches"`
	Total   int64           `json:"total"`
	Limit   int32           `json:"limit"`
	Offset  int32           `json:"offset"`
}
