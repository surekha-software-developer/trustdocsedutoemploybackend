package blockchain

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// BlockchainClient defines the required EVM interactions for anchoring.
type BlockchainClient interface {
	GetPendingNonce(ctx context.Context, address string) (uint64, error)
	EstimateGas(ctx context.Context, callMsg CallMsg) (uint64, error)
	GetFeeData(ctx context.Context) (*FeeData, error)
	BroadcastTransaction(ctx context.Context, signedRawHex string) (string, error)
	GetTransactionReceipt(ctx context.Context, txHash string) (*Receipt, error)
	GetBlockByNumber(ctx context.Context, blockNumber uint64) (*BlockHeader, error)
	GetBlockHeight(ctx context.Context) (uint64, error)
}

// RPCClient communicates with an EVM node via standard JSON-RPC 2.0 over HTTP.
type RPCClient struct {
	rpcURL     string
	httpClient *http.Client
	requestID  uint64
}

// NewRPCClient constructs an RPCClient with the provided endpoint and timeout.
func NewRPCClient(rpcURL string, timeout time.Duration) *RPCClient {
	return &RPCClient{
		rpcURL: rpcURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

type jsonRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      uint64        `json:"id"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *jsonRPCError) Error() string {
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

func (c *RPCClient) call(ctx context.Context, method string, params ...interface{}) (json.RawMessage, error) {
	reqID := atomic.AddUint64(&c.requestID, 1)
	rpcReq := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      reqID,
	}

	bodyBytes, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal rpc request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.rpcURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("rpc http call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("rpc http status %d", resp.StatusCode)
	}

	var rpcResp jsonRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("failed to decode rpc response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, rpcResp.Error
	}

	return rpcResp.Result, nil
}

// GetPendingNonce queries eth_getTransactionCount for the address at 'pending' tag.
func (c *RPCClient) GetPendingNonce(ctx context.Context, address string) (uint64, error) {
	raw, err := c.call(ctx, "eth_getTransactionCount", address, "pending")
	if err != nil {
		return 0, err
	}

	var hexStr string
	if err := json.Unmarshal(raw, &hexStr); err != nil {
		return 0, fmt.Errorf("failed to unmarshal nonce hex: %w", err)
	}

	nonce, err := parseHexUint64(hexStr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse nonce hex '%s': %w", hexStr, err)
	}
	return nonce, nil
}

// EstimateGas estimates gas consumption for the callMsg.
func (c *RPCClient) EstimateGas(ctx context.Context, callMsg CallMsg) (uint64, error) {
	payload := map[string]interface{}{
		"to":   callMsg.To,
		"data": "0x" + hex.EncodeToString(callMsg.Data),
	}
	if callMsg.From != "" {
		payload["from"] = callMsg.From
	}

	raw, err := c.call(ctx, "eth_estimateGas", payload)
	if err != nil {
		return 0, err
	}

	var hexStr string
	if err := json.Unmarshal(raw, &hexStr); err != nil {
		return 0, fmt.Errorf("failed to unmarshal gas hex: %w", err)
	}

	return parseHexUint64(hexStr)
}

// GetFeeData retrieves EIP-1559 baseFee and priorityFee recommendations.
func (c *RPCClient) GetFeeData(ctx context.Context) (*FeeData, error) {
	// 1. eth_maxPriorityFeePerGas
	rawTip, err := c.call(ctx, "eth_maxPriorityFeePerGas")
	var tipHex string
	if err == nil {
		_ = json.Unmarshal(rawTip, &tipHex)
	}
	tip := parseHexBigInt(tipHex)
	if tip == nil || tip.Sign() == 0 {
		// Default 1.5 Gwei tip if unavailable
		tip = big.NewInt(1500000000)
	}

	// 2. eth_getBlockByNumber("latest", false)
	rawBlock, err := c.call(ctx, "eth_getBlockByNumber", "latest", false)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest block: %w", err)
	}

	var blockData struct {
		BaseFeePerGas string `json:"baseFeePerGas"`
	}
	if err := json.Unmarshal(rawBlock, &blockData); err != nil {
		return nil, fmt.Errorf("failed to parse block header: %w", err)
	}

	baseFee := parseHexBigInt(blockData.BaseFeePerGas)
	if baseFee == nil {
		baseFee = big.NewInt(1000000000) // 1 Gwei fallback
	}

	// maxFeePerGas = 2 * baseFee + tip
	maxFee := new(big.Int).Mul(baseFee, big.NewInt(2))
	maxFee.Add(maxFee, tip)

	return &FeeData{
		BaseFee:              baseFee,
		MaxPriorityFeePerGas: tip,
		MaxFeePerGas:         maxFee,
	}, nil
}

// BroadcastTransaction submits a signed raw transaction to the mempool.
func (c *RPCClient) BroadcastTransaction(ctx context.Context, signedRawHex string) (string, error) {
	raw, err := c.call(ctx, "eth_sendRawTransaction", signedRawHex)
	if err != nil {
		errMsg := strings.ToLower(err.Error())
		// Treat already known transaction idempotently
		if strings.Contains(errMsg, "already known") ||
			strings.Contains(errMsg, "transaction already exists") ||
			strings.Contains(errMsg, "known transaction") {
			return "", nil
		}
		return "", err
	}

	var txHash string
	if err := json.Unmarshal(raw, &txHash); err != nil {
		return "", fmt.Errorf("failed to unmarshal tx hash: %w", err)
	}
	return txHash, nil
}

// GetTransactionReceipt queries eth_getTransactionReceipt. Returns nil if pending/not found.
func (c *RPCClient) GetTransactionReceipt(ctx context.Context, txHash string) (*Receipt, error) {
	raw, err := c.call(ctx, "eth_getTransactionReceipt", txHash)
	if err != nil {
		return nil, err
	}

	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	var rawReceipt struct {
		TransactionHash   string `json:"transactionHash"`
		Status            string `json:"status"`
		BlockNumber       string `json:"blockNumber"`
		BlockHash         string `json:"blockHash"`
		GasUsed           string `json:"gasUsed"`
		ContractAddress   string `json:"contractAddress"`
		EffectiveGasPrice string `json:"effectiveGasPrice"`
		Logs              []struct {
			Address     string   `json:"address"`
			Topics      []string `json:"topics"`
			Data        string   `json:"data"`
			BlockNumber string   `json:"blockNumber"`
			TxHash      string   `json:"transactionHash"`
			LogIndex    string   `json:"logIndex"`
			Removed     bool     `json:"removed"`
		} `json:"logs"`
	}

	if err := json.Unmarshal(raw, &rawReceipt); err != nil {
		return nil, fmt.Errorf("failed to decode receipt json: %w", err)
	}

	status, _ := parseHexUint64(rawReceipt.Status)
	blockNum, _ := parseHexUint64(rawReceipt.BlockNumber)
	gasUsed, _ := parseHexUint64(rawReceipt.GasUsed)

	logs := make([]Log, 0, len(rawReceipt.Logs))
	for _, l := range rawReceipt.Logs {
		dataBytes, _ := hex.DecodeString(strings.TrimPrefix(l.Data, "0x"))
		lIndex, _ := parseHexUint64(l.LogIndex)
		lBlockNum, _ := parseHexUint64(l.BlockNumber)
		logs = append(logs, Log{
			Address:     l.Address,
			Topics:      l.Topics,
			Data:        dataBytes,
			BlockNumber: lBlockNum,
			TxHash:      l.TxHash,
			Index:       uint(lIndex),
			Removed:     l.Removed,
		})
	}

	return &Receipt{
		TxHash:            rawReceipt.TransactionHash,
		Status:            status,
		BlockNumber:       blockNum,
		BlockHash:         rawReceipt.BlockHash,
		GasUsed:           gasUsed,
		Logs:              logs,
		ContractAddress:   rawReceipt.ContractAddress,
		EffectiveGasPrice: parseHexBigInt(rawReceipt.EffectiveGasPrice),
	}, nil
}

// GetBlockByNumber queries block information by number.
func (c *RPCClient) GetBlockByNumber(ctx context.Context, blockNumber uint64) (*BlockHeader, error) {
	blockHex := fmt.Sprintf("0x%x", blockNumber)
	raw, err := c.call(ctx, "eth_getBlockByNumber", blockHex, false)
	if err != nil {
		return nil, err
	}

	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	var blockData struct {
		Number        string `json:"number"`
		Hash          string `json:"hash"`
		ParentHash    string `json:"parentHash"`
		Timestamp     string `json:"timestamp"`
		BaseFeePerGas string `json:"baseFeePerGas"`
	}
	if err := json.Unmarshal(raw, &blockData); err != nil {
		return nil, fmt.Errorf("failed to decode block json: %w", err)
	}

	bNum, _ := parseHexUint64(blockData.Number)
	bTime, _ := parseHexUint64(blockData.Timestamp)

	return &BlockHeader{
		Number:     bNum,
		Hash:       blockData.Hash,
		ParentHash: blockData.ParentHash,
		Timestamp:  time.Unix(int64(bTime), 0).UTC(),
		BaseFee:    parseHexBigInt(blockData.BaseFeePerGas),
	}, nil
}

// GetBlockHeight queries current latest block number.
func (c *RPCClient) GetBlockHeight(ctx context.Context) (uint64, error) {
	raw, err := c.call(ctx, "eth_blockNumber")
	if err != nil {
		return 0, err
	}

	var hexStr string
	if err := json.Unmarshal(raw, &hexStr); err != nil {
		return 0, fmt.Errorf("failed to decode blockNumber json: %w", err)
	}

	return parseHexUint64(hexStr)
}

func parseHexUint64(hexStr string) (uint64, error) {
	clean := strings.TrimPrefix(strings.TrimSpace(hexStr), "0x")
	if clean == "" {
		return 0, nil
	}
	return strconv.ParseUint(clean, 16, 64)
}

func parseHexBigInt(hexStr string) *big.Int {
	clean := strings.TrimPrefix(strings.TrimSpace(hexStr), "0x")
	if clean == "" {
		return nil
	}
	n := new(big.Int)
	n.SetString(clean, 16)
	return n
}
