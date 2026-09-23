package blockchain

import (
	"math/big"
	"time"
)

// CallMsg contains parameters for eth_estimateGas and eth_call.
type CallMsg struct {
	From     string   `json:"from,omitempty"`
	To       string   `json:"to"`
	Gas      uint64   `json:"gas,omitempty"`
	GasPrice *big.Int `json:"gasPrice,omitempty"`
	Value    *big.Int `json:"value,omitempty"`
	Data     []byte   `json:"data"`
}

// UnsignedTx represents an unsigned EIP-1559 (Type 2) transaction.
type UnsignedTx struct {
	ChainID              *big.Int `json:"chainId"`
	Nonce                uint64   `json:"nonce"`
	MaxPriorityFeePerGas *big.Int `json:"maxPriorityFeePerGas"`
	MaxFeePerGas         *big.Int `json:"maxFeePerGas"`
	GasLimit             uint64   `json:"gasLimit"`
	To                   string   `json:"to"`
	Value                *big.Int `json:"value"`
	Data                 []byte   `json:"data"`
	AccessList           []byte   `json:"accessList,omitempty"`
}

// FeeData contains suggested EIP-1559 gas fee parameters.
type FeeData struct {
	BaseFee              *big.Int `json:"baseFee"`
	MaxPriorityFeePerGas *big.Int `json:"maxPriorityFeePerGas"`
	MaxFeePerGas         *big.Int `json:"maxFeePerGas"`
}

// Receipt represents a mined transaction receipt.
type Receipt struct {
	TxHash            string   `json:"transactionHash"`
	Status            uint64   `json:"status"` // 1 = success, 0 = reverted
	BlockNumber       uint64   `json:"blockNumber"`
	BlockHash         string   `json:"blockHash"`
	GasUsed           uint64   `json:"gasUsed"`
	Logs              []Log    `json:"logs"`
	ContractAddress   string   `json:"contractAddress,omitempty"`
	EffectiveGasPrice *big.Int `json:"effectiveGasPrice,omitempty"`
}

// Log represents an EVM event log.
type Log struct {
	Address     string   `json:"address"`
	Topics      []string `json:"topics"`
	Data        []byte   `json:"data"`
	BlockNumber uint64   `json:"blockNumber"`
	TxHash      string   `json:"transactionHash"`
	Index       uint     `json:"logIndex"`
	Removed     bool     `json:"removed"`
}

// BlockHeader represents block header information needed for confirmation and reorg verification.
type BlockHeader struct {
	Number     uint64    `json:"number"`
	Hash       string    `json:"hash"`
	ParentHash string    `json:"parentHash"`
	Timestamp  time.Time `json:"timestamp"`
	BaseFee    *big.Int  `json:"baseFeePerGas,omitempty"`
}

// RootAnchoredEvent holds the decoded event payload emitted by TrustDocsAnchor.
type RootAnchoredEvent struct {
	MerkleRoot       string    `json:"merkleRoot"`
	CanonicalBatchID string    `json:"canonicalBatchId"`
	Submitter        string    `json:"submitter"`
	CertificateCount uint32    `json:"certificateCount"`
	AnchoredAt       time.Time `json:"anchoredAt"`
	BlockNumber      uint64    `json:"blockNumber"`
	TxHash           string    `json:"txHash"`
}
