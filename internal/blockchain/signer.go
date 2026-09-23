package blockchain

import (
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Function and Event Signatures for TrustDocsAnchor.sol
var (
	// AnchorRootSelector is the 4-byte selector for anchorRoot(bytes32,bytes32,uint32).
	AnchorRootSelector = computeAnchorRootSelector()

	// IsAnchorerSelector is the 4-byte selector for isAnchorer(address).
	IsAnchorerSelector = computeIsAnchorerSelector()

	// TopicRootAnchored is the 32-byte topic for RootAnchored(bytes32,bytes32,address,uint32,uint64).
	TopicRootAnchored = ComputeKeccak256([]byte("RootAnchored(bytes32,bytes32,address,uint32,uint64)"))
)

func computeAnchorRootSelector() [4]byte {
	hash := ComputeKeccak256([]byte("anchorRoot(bytes32,bytes32,uint32)"))
	var sel [4]byte
	copy(sel[:], hash[:4])
	return sel
}

func computeIsAnchorerSelector() [4]byte {
	hash := ComputeKeccak256([]byte("isAnchorer(address)"))
	var sel [4]byte
	copy(sel[:], hash[:4])
	return sel
}

// Signer signs EIP-1559 transactions and provides signer address and chain identity.
type Signer interface {
	Address() string
	ChainID() *big.Int
	SignTransaction(tx *UnsignedTx) (signedRawHex string, txHash string, err error)
}

// ComputeKeccak256 returns the 32-byte Keccak-256 digest of data.
func ComputeKeccak256(data []byte) [32]byte {
	return crypto.Keccak256Hash(data)
}

// ValidateAndParseAddress strictly validates an Ethereum address string:
// - Must be exactly 42 characters
// - Must start with lowercase '0x'
// - Must be valid hex characters (common.IsHexAddress)
// Reject empty, short, oversized, malformed, and uppercase '0X' prefix.
func ValidateAndParseAddress(addr string) (common.Address, error) {
	if len(addr) != 42 {
		return common.Address{}, fmt.Errorf("invalid address length: expected 42 characters, got %d", len(addr))
	}
	if !strings.HasPrefix(addr, "0x") {
		return common.Address{}, fmt.Errorf("invalid address prefix: must start with lowercase '0x'")
	}
	if !common.IsHexAddress(addr) {
		return common.Address{}, fmt.Errorf("invalid address hex characters: %s", addr)
	}
	return common.HexToAddress(addr), nil
}

// EncodeAnchorRootCalldata packs function arguments for TrustDocsAnchor.anchorRoot(bytes32,bytes32,uint32).
func EncodeAnchorRootCalldata(root [32]byte, canonicalBatchID [32]byte, certificateCount uint32) []byte {
	calldata := make([]byte, 4+32+32+32)
	copy(calldata[:4], AnchorRootSelector[:])
	copy(calldata[4:36], root[:])
	copy(calldata[36:68], canonicalBatchID[:])
	binary.BigEndian.PutUint32(calldata[96:100], certificateCount)
	return calldata
}

// EncodeIsAnchorerCalldata packs function arguments for TrustDocsAnchor.isAnchorer(address).
func EncodeIsAnchorerCalldata(account common.Address) []byte {
	calldata := make([]byte, 4+32)
	copy(calldata[:4], IsAnchorerSelector[:])
	copy(calldata[16:36], account.Bytes())
	return calldata
}

// ParseAndValidateRootAnchoredEvent extracts and verifies the RootAnchored event from a transaction receipt.
func ParseAndValidateRootAnchoredEvent(
	receipt *Receipt,
	contractAddress string,
	expectedRoot [32]byte,
	expectedBatchID [32]byte,
	expectedSubmitter string,
	expectedCertificateCount uint32,
) (*RootAnchoredEvent, error) {
	if receipt == nil {
		return nil, fmt.Errorf("receipt is nil")
	}
	if receipt.Status != 1 {
		return nil, fmt.Errorf("transaction execution failed or reverted with status %d", receipt.Status)
	}

	expectedContractAddr, err := ValidateAndParseAddress(contractAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid contract address: %w", err)
	}

	expectedSubmitterAddr, err := ValidateAndParseAddress(expectedSubmitter)
	if err != nil {
		return nil, fmt.Errorf("invalid expected submitter address: %w", err)
	}

	expectedRootHex := "0x" + hex.EncodeToString(expectedRoot[:])
	expectedBatchIDHex := "0x" + hex.EncodeToString(expectedBatchID[:])
	expectedTopic0 := "0x" + hex.EncodeToString(TopicRootAnchored[:])

	var foundLog *Log
	for i := range receipt.Logs {
		log := &receipt.Logs[i]
		if !strings.EqualFold(log.Address, expectedContractAddr.Hex()) {
			continue
		}
		if len(log.Topics) >= 1 && strings.EqualFold(log.Topics[0], expectedTopic0) {
			foundLog = log
			break
		}
	}

	if foundLog == nil {
		return nil, fmt.Errorf("RootAnchored event not found in transaction logs for contract %s", contractAddress)
	}

	if len(foundLog.Topics) != 4 {
		return nil, fmt.Errorf("invalid RootAnchored event topic count: expected 4, got %d", len(foundLog.Topics))
	}

	// Validate every topic is exactly 0x + 64 hex characters
	topicBytes := make([][32]byte, 4)
	for i, topic := range foundLog.Topics {
		if len(topic) != 66 {
			return nil, fmt.Errorf("topic %d length invalid: expected 66 characters, got %d", i, len(topic))
		}
		if !strings.HasPrefix(topic, "0x") {
			return nil, fmt.Errorf("topic %d prefix invalid: must start with lowercase '0x'", i)
		}
		raw, err := hex.DecodeString(topic[2:])
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("topic %d hex decoding failed: %w", i, err)
		}
		copy(topicBytes[i][:], raw)
	}

	// Topic 0: Event signature
	if topicBytes[0] != TopicRootAnchored {
		return nil, fmt.Errorf("event topic 0 mismatch")
	}

	// Topic 1: Merkle Root
	if topicBytes[1] != expectedRoot {
		return nil, fmt.Errorf("event merkle root mismatch: expected %s, got %s", expectedRootHex, foundLog.Topics[1])
	}

	// Topic 2: Canonical Batch ID
	if topicBytes[2] != expectedBatchID {
		return nil, fmt.Errorf("event canonical batch ID mismatch: expected %s, got %s", expectedBatchIDHex, foundLog.Topics[2])
	}

	// Topic 3: Submitter address (first 12 raw bytes must be zero)
	for i := 0; i < 12; i++ {
		if topicBytes[3][i] != 0 {
			return nil, fmt.Errorf("indexed submitter topic first 12 bytes must be zero, got non-zero at index %d", i)
		}
	}
	submitterAddr := common.BytesToAddress(topicBytes[3][12:])
	if submitterAddr != expectedSubmitterAddr {
		return nil, fmt.Errorf("event submitter mismatch: expected %s, got %s", expectedSubmitterAddr.Hex(), submitterAddr.Hex())
	}

	// Non-indexed data: must be exactly 64 bytes
	if len(foundLog.Data) != 64 {
		return nil, fmt.Errorf("invalid RootAnchored event data length: expected exactly 64 bytes, got %d", len(foundLog.Data))
	}

	// Word 0: certificateCount (uint32) - high 28 bytes must be zero
	for i := 0; i < 28; i++ {
		if foundLog.Data[i] != 0 {
			return nil, fmt.Errorf("invalid uint32 padding in event data: high 28 bytes must be zero")
		}
	}
	certCount := binary.BigEndian.Uint32(foundLog.Data[28:32])
	if certCount != expectedCertificateCount {
		return nil, fmt.Errorf("event certificate count mismatch: expected %d, got %d", expectedCertificateCount, certCount)
	}

	// Word 1: anchoredAt timestamp (uint64) - high 24 bytes must be zero
	for i := 32; i < 56; i++ {
		if foundLog.Data[i] != 0 {
			return nil, fmt.Errorf("invalid uint64 padding in event data: high 24 bytes must be zero")
		}
	}
	anchoredTimestampSec := binary.BigEndian.Uint64(foundLog.Data[56:64])
	anchoredAt := time.Unix(int64(anchoredTimestampSec), 0).UTC()

	return &RootAnchoredEvent{
		MerkleRoot:       foundLog.Topics[1],
		CanonicalBatchID: foundLog.Topics[2],
		Submitter:        submitterAddr.Hex(),
		CertificateCount: certCount,
		AnchoredAt:       anchoredAt,
		BlockNumber:      receipt.BlockNumber,
		TxHash:           receipt.TxHash,
	}, nil
}

// ComputeEIP1559SigningHash derives the keccak256 signing hash for an EIP-1559 transaction using LondonSigner.
func ComputeEIP1559SigningHash(tx *UnsignedTx) ([32]byte, error) {
	if tx == nil {
		return [32]byte{}, fmt.Errorf("transaction is nil")
	}
	if tx.ChainID == nil || tx.ChainID.Sign() <= 0 {
		return [32]byte{}, fmt.Errorf("invalid chain ID")
	}
	toAddr, err := ValidateAndParseAddress(tx.To)
	if err != nil {
		return [32]byte{}, fmt.Errorf("invalid destination address: %w", err)
	}
	val := tx.Value
	if val == nil {
		val = big.NewInt(0)
	}

	dynamicTx := &types.DynamicFeeTx{
		ChainID:    tx.ChainID,
		Nonce:      tx.Nonce,
		GasTipCap:  tx.MaxPriorityFeePerGas,
		GasFeeCap:  tx.MaxFeePerGas,
		Gas:        tx.GasLimit,
		To:         &toAddr,
		Value:      val,
		Data:       tx.Data,
		AccessList: nil,
	}

	signer := types.NewLondonSigner(tx.ChainID)
	h := signer.Hash(types.NewTx(dynamicTx))
	var out [32]byte
	copy(out[:], h.Bytes())
	return out, nil
}

// DeterministicSigner implements Signer using standard Ethereum secp256k1 EIP-1559 signing.
type DeterministicSigner struct {
	address    common.Address
	chainID    *big.Int
	privateKey *ecdsa.PrivateKey
}

// NewDeterministicSigner creates a Signer for offline deterministic signing.
func NewDeterministicSigner(address string, chainID int64, privateKeyHex string) (*DeterministicSigner, error) {
	parsedAddr, err := ValidateAndParseAddress(address)
	if err != nil {
		return nil, fmt.Errorf("invalid signer address: %w", err)
	}

	if chainID <= 0 {
		return nil, fmt.Errorf("invalid chain ID: must be positive")
	}

	cleanKey := strings.TrimSpace(privateKeyHex)
	cleanKey = strings.TrimPrefix(cleanKey, "0x")
	cleanKey = strings.TrimPrefix(cleanKey, "0X")
	if len(cleanKey) != 64 {
		return nil, fmt.Errorf("invalid private key length: expected 64 hex characters, got %d", len(cleanKey))
	}

	privKey, err := crypto.HexToECDSA(cleanKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	// Validate private key range: 1 <= k < N
	secp256k1N := crypto.S256().Params().N
	if privKey.D == nil || privKey.D.Sign() <= 0 || privKey.D.Cmp(secp256k1N) >= 0 {
		return nil, fmt.Errorf("invalid private key: out of secp256k1 curve range")
	}

	derivedAddr := crypto.PubkeyToAddress(privKey.PublicKey)
	if parsedAddr != derivedAddr {
		return nil, fmt.Errorf("configured address %s does not match private key derived address %s", parsedAddr.Hex(), derivedAddr.Hex())
	}

	return &DeterministicSigner{
		address:    derivedAddr,
		chainID:    big.NewInt(chainID),
		privateKey: privKey,
	}, nil
}

// Address returns the configured signer address in canonical EIP-55 format.
func (s *DeterministicSigner) Address() string {
	return s.address.Hex()
}

// ChainID returns the configured chain ID.
func (s *DeterministicSigner) ChainID() *big.Int {
	return new(big.Int).Set(s.chainID)
}

// SignTransaction signs an EIP-1559 transaction using London signer and returns signedRawHex and the txHash.
// Note: The raw signed bytes are returned for in-memory broadcast only and must never be persisted or logged.
func (s *DeterministicSigner) SignTransaction(tx *UnsignedTx) (string, string, error) {
	if tx == nil {
		return "", "", fmt.Errorf("transaction is nil")
	}
	if tx.ChainID == nil || s.chainID.Cmp(tx.ChainID) != 0 {
		return "", "", fmt.Errorf("chain ID mismatch")
	}
	toAddr, err := ValidateAndParseAddress(tx.To)
	if err != nil {
		return "", "", fmt.Errorf("invalid destination address: %w", err)
	}
	if tx.GasLimit == 0 {
		return "", "", fmt.Errorf("gas limit cannot be 0")
	}
	if tx.MaxFeePerGas == nil || tx.MaxPriorityFeePerGas == nil {
		return "", "", fmt.Errorf("fees cannot be nil")
	}
	if tx.MaxFeePerGas.Sign() < 0 || tx.MaxPriorityFeePerGas.Sign() < 0 {
		return "", "", fmt.Errorf("fees cannot be negative")
	}
	secp256k1Max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	if tx.MaxFeePerGas.Cmp(secp256k1Max) > 0 || tx.MaxPriorityFeePerGas.Cmp(secp256k1Max) > 0 {
		return "", "", fmt.Errorf("fees exceed uint256 max")
	}
	if tx.MaxFeePerGas.Cmp(tx.MaxPriorityFeePerGas) < 0 {
		return "", "", fmt.Errorf("maxFeePerGas cannot be less than maxPriorityFeePerGas")
	}

	val := tx.Value
	if val == nil {
		val = big.NewInt(0)
	}
	if val.Sign() < 0 || val.Cmp(secp256k1Max) > 0 {
		return "", "", fmt.Errorf("value invalid")
	}

	dynamicTx := &types.DynamicFeeTx{
		ChainID:    tx.ChainID,
		Nonce:      tx.Nonce,
		GasTipCap:  tx.MaxPriorityFeePerGas,
		GasFeeCap:  tx.MaxFeePerGas,
		Gas:        tx.GasLimit,
		To:         &toAddr,
		Value:      val,
		Data:       tx.Data,
		AccessList: nil,
	}

	signer := types.NewLondonSigner(s.chainID)
	signedTx, err := types.SignTx(types.NewTx(dynamicTx), signer, s.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	sender, err := types.Sender(signer, signedTx)
	if err != nil {
		return "", "", fmt.Errorf("failed to recover sender from signed transaction: %w", err)
	}
	if sender != s.address {
		return "", "", fmt.Errorf("recovered sender %s does not match signer address %s", sender.Hex(), s.address.Hex())
	}

	rawBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal binary transaction: %w", err)
	}

	signedRawHex := "0x" + hex.EncodeToString(rawBytes)
	txHash := signedTx.Hash().Hex()
	return signedRawHex, txHash, nil
}
