package blockchain

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// MockBlockchainClient provides a thread-safe in-memory blockchain client for tests.
type MockBlockchainClient struct {
	mu sync.RWMutex

	PendingNonce      uint64
	EstimateGasResult uint64
	FeeDataResult     *FeeData
	BroadcastTxResult string
	Receipts          map[string]*Receipt
	BlockHeaders      map[uint64]*BlockHeader
	BlockHeight       uint64
	BroadcastedTxs    []string

	GetPendingNonceErr       error
	EstimateGasErr           error
	GetFeeDataErr            error
	BroadcastTransactionErr  error
	GetTransactionReceiptErr error
	GetBlockByNumberErr      error
	GetBlockHeightErr        error
}

// NewMockBlockchainClient creates a initialized mock client with realistic test defaults.
func NewMockBlockchainClient() *MockBlockchainClient {
	return &MockBlockchainClient{
		PendingNonce:      0,
		EstimateGasResult: 150000,
		FeeDataResult: &FeeData{
			BaseFee:              big.NewInt(1000000000), // 1 Gwei
			MaxPriorityFeePerGas: big.NewInt(1500000000), // 1.5 Gwei
			MaxFeePerGas:         big.NewInt(3500000000), // 3.5 Gwei
		},
		Receipts:     make(map[string]*Receipt),
		BlockHeaders: make(map[uint64]*BlockHeader),
		BlockHeight:  100,
	}
}

func (m *MockBlockchainClient) GetPendingNonce(ctx context.Context, address string) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.GetPendingNonceErr != nil {
		return 0, m.GetPendingNonceErr
	}
	return m.PendingNonce, nil
}

func (m *MockBlockchainClient) EstimateGas(ctx context.Context, callMsg CallMsg) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.EstimateGasErr != nil {
		return 0, m.EstimateGasErr
	}
	return m.EstimateGasResult, nil
}

func (m *MockBlockchainClient) GetFeeData(ctx context.Context) (*FeeData, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.GetFeeDataErr != nil {
		return nil, m.GetFeeDataErr
	}
	return m.FeeDataResult, nil
}

func (m *MockBlockchainClient) BroadcastTransaction(ctx context.Context, signedRawHex string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.BroadcastTransactionErr != nil {
		return "", m.BroadcastTransactionErr
	}
	m.BroadcastedTxs = append(m.BroadcastedTxs, signedRawHex)
	if m.BroadcastTxResult != "" {
		return m.BroadcastTxResult, nil
	}
	// Compute hash of the payload as fallback
	rawBytes, _ := hex.DecodeString(signedRawHex[2:])
	h := ComputeKeccak256(rawBytes)
	return "0x" + hex.EncodeToString(h[:]), nil
}

func (m *MockBlockchainClient) GetTransactionReceipt(ctx context.Context, txHash string) (*Receipt, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.GetTransactionReceiptErr != nil {
		return nil, m.GetTransactionReceiptErr
	}
	return m.Receipts[txHash], nil
}

func (m *MockBlockchainClient) GetBlockByNumber(ctx context.Context, blockNumber uint64) (*BlockHeader, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.GetBlockByNumberErr != nil {
		return nil, m.GetBlockByNumberErr
	}
	return m.BlockHeaders[blockNumber], nil
}

func (m *MockBlockchainClient) GetBlockHeight(ctx context.Context) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.GetBlockHeightErr != nil {
		return 0, m.GetBlockHeightErr
	}
	return m.BlockHeight, nil
}

// AddMockReceipt records a successful RootAnchored transaction receipt and corresponding block.
func (m *MockBlockchainClient) AddMockReceipt(
	txHash string,
	contractAddress string,
	root [32]byte,
	batchID [32]byte,
	submitter string,
	certificateCount uint32,
	blockNumber uint64,
	blockHash string,
) {
	m.mu.Lock()
	defer m.mu.Unlock()

	data := make([]byte, 64)
	binary.BigEndian.PutUint32(data[28:32], certificateCount)
	binary.BigEndian.PutUint64(data[56:64], uint64(time.Now().Unix()))

	submitterClean := submitter
	if len(submitterClean) >= 2 && submitterClean[:2] == "0x" {
		submitterClean = submitterClean[2:]
	}
	submitterTopic := "0x" + fmt.Sprintf("%024s%s", "0", submitterClean)

	log := Log{
		Address: contractAddress,
		Topics: []string{
			"0x" + hex.EncodeToString(TopicRootAnchored[:]),
			"0x" + hex.EncodeToString(root[:]),
			"0x" + hex.EncodeToString(batchID[:]),
			submitterTopic,
		},
		Data:        data,
		BlockNumber: blockNumber,
		TxHash:      txHash,
		Index:       0,
	}

	m.Receipts[txHash] = &Receipt{
		TxHash:          txHash,
		Status:          1,
		BlockNumber:     blockNumber,
		BlockHash:       blockHash,
		GasUsed:         75000,
		Logs:            []Log{log},
		ContractAddress: contractAddress,
	}

	m.BlockHeaders[blockNumber] = &BlockHeader{
		Number:     blockNumber,
		Hash:       blockHash,
		ParentHash: fmt.Sprintf("0xparent%d", blockNumber),
		Timestamp:  time.Now().UTC(),
	}

	if blockNumber > m.BlockHeight {
		m.BlockHeight = blockNumber
	}
}

// AddMockRevertedReceipt records a reverted transaction receipt and corresponding block header safely.
func (m *MockBlockchainClient) AddMockRevertedReceipt(
	txHash string,
	contractAddress string,
	blockNumber uint64,
	blockHash string,
) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Receipts[txHash] = &Receipt{
		TxHash:          txHash,
		Status:          0,
		BlockNumber:     blockNumber,
		BlockHash:       blockHash,
		GasUsed:         75000,
		Logs:            []Log{},
		ContractAddress: contractAddress,
	}

	m.BlockHeaders[blockNumber] = &BlockHeader{
		Number:     blockNumber,
		Hash:       blockHash,
		ParentHash: fmt.Sprintf("0xparent%d", blockNumber),
		Timestamp:  time.Now().UTC(),
	}

	if blockNumber > m.BlockHeight {
		m.BlockHeight = blockNumber
	}
}

// BroadcastCount returns the number of broadcasted transactions safely.
func (m *MockBlockchainClient) BroadcastCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.BroadcastedTxs)
}

// SetBlockHeight updates the simulated blockchain block height safely.
func (m *MockBlockchainClient) SetBlockHeight(height uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.BlockHeight = height
}

// SetFeeData updates the simulated fee data safely.
func (m *MockBlockchainClient) SetFeeData(data *FeeData) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FeeDataResult = data
}

// SetReceiptStatus updates the status of an existing receipt safely.
// Returns true only when a non-nil receipt exists and is updated; false otherwise.
func (m *MockBlockchainClient) SetReceiptStatus(txHash string, status uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.Receipts[txHash]
	if !ok || r == nil {
		return false
	}
	r.Status = status
	return true
}

// SetBlockHeader records or overrides a block header safely, making an internal copy.
func (m *MockBlockchainClient) SetBlockHeader(blockNumber uint64, header *BlockHeader) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if header != nil {
		cp := *header
		m.BlockHeaders[blockNumber] = &cp
	} else {
		delete(m.BlockHeaders, blockNumber)
	}
}

// MockSigner provides a controllable transaction signer for tests.
type MockSigner struct {
	MockAddress     string
	MockChainID     *big.Int
	SignErr         error
	PredictedTxHash string
	SignedHex       string
}

// NewMockSigner creates a MockSigner with specified address and chainID.
func NewMockSigner(address string, chainID int64) *MockSigner {
	return &MockSigner{
		MockAddress: address,
		MockChainID: big.NewInt(chainID),
	}
}

func (s *MockSigner) Address() string {
	return s.MockAddress
}

func (s *MockSigner) ChainID() *big.Int {
	return s.MockChainID
}

func (s *MockSigner) SignTransaction(tx *UnsignedTx) (string, string, error) {
	if s.SignErr != nil {
		return "", "", s.SignErr
	}

	h, _ := ComputeEIP1559SigningHash(tx)
	predHash := s.PredictedTxHash
	if predHash == "" {
		predHash = "0x" + hex.EncodeToString(h[:])
	}

	signedHex := s.SignedHex
	if signedHex == "" {
		signedHex = "0x02" + hex.EncodeToString(h[:])
	}

	return signedHex, predHash, nil
}
