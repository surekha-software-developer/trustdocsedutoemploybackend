package blockchain

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestRLP_Encoding(t *testing.T) {
	// Single byte < 0x80
	b := RLPEncodeBytes([]byte{0x42})
	if len(b) != 1 || b[0] != 0x42 {
		t.Errorf("expected [0x42], got %x", b)
	}

	// Empty string
	empty := RLPEncodeBytes([]byte{})
	if len(empty) != 1 || empty[0] != 0x80 {
		t.Errorf("expected [0x80], got %x", empty)
	}

	// Short string
	dog := RLPEncodeBytes([]byte("dog"))
	if len(dog) != 4 || dog[0] != 0x83 || string(dog[1:]) != "dog" {
		t.Errorf("expected 0x83 'dog', got %x", dog)
	}

	// Uint64 0
	u0 := RLPEncodeUint64(0)
	if len(u0) != 1 || u0[0] != 0x80 {
		t.Errorf("expected 0x80 for 0, got %x", u0)
	}

	// Uint64 15
	u15 := RLPEncodeUint64(15)
	if len(u15) != 1 || u15[0] != 15 {
		t.Errorf("expected [15], got %x", u15)
	}

	// BigInt 1000
	bi := RLPEncodeBigInt(big.NewInt(1000))
	if len(bi) != 3 || bi[0] != 0x82 {
		t.Errorf("expected 0x82 followed by 2 bytes, got %x", bi)
	}

	// Empty list
	emptyList := RLPEncodeList(nil)
	if len(emptyList) != 1 || emptyList[0] != 0xc0 {
		t.Errorf("expected 0xc0 for empty list, got %x", emptyList)
	}
}

func TestEncodeAnchorRootCalldata(t *testing.T) {
	var root [32]byte
	var batchID [32]byte
	copy(root[:], []byte("root-123456789012345678901234567"))
	copy(batchID[:], []byte("batch-12345678901234567890123456"))
	const certCount = uint32(42)

	calldata := EncodeAnchorRootCalldata(root, batchID, certCount)
	// 1. Ensure calldata length is exactly 100 bytes (4-byte selector + three 32-byte ABI words)
	if len(calldata) != 100 {
		t.Fatalf("expected exactly 100 bytes calldata, got %d", len(calldata))
	}

	// 2. Independently compute the selector using Keccak256("anchorRoot(bytes32,bytes32,uint32)")[:4]
	computedSelector := crypto.Keccak256([]byte("anchorRoot(bytes32,bytes32,uint32)"))[:4]
	expectedSelector := [4]byte{0x9f, 0x4d, 0x6d, 0x5d}
	if !bytes.Equal(computedSelector, expectedSelector[:]) {
		t.Fatalf("computed selector mismatch: got %x, expected %x", computedSelector, expectedSelector)
	}

	// 3. Assert that production AnchorRootSelector equals 0x9f4d6d5d
	if AnchorRootSelector != expectedSelector {
		t.Errorf("AnchorRootSelector mismatch: expected %x, got %x", expectedSelector, AnchorRootSelector)
	}

	// 4. Check selector in calldata
	if !bytes.Equal(calldata[:4], expectedSelector[:]) {
		t.Errorf("calldata selector mismatch: %x vs %x", calldata[:4], expectedSelector)
	}

	// 5. Check root
	if !bytes.Equal(calldata[4:36], root[:]) {
		t.Errorf("calldata root mismatch")
	}

	// 6. Check batch ID
	if !bytes.Equal(calldata[36:68], batchID[:]) {
		t.Errorf("calldata batchID mismatch")
	}

	// 7. Check certificate count zero padding and value
	for i := 68; i < 96; i++ {
		if calldata[i] != 0 {
			t.Errorf("expected zero padding at calldata index %d, got %x", i, calldata[i])
		}
	}
	count := binary.BigEndian.Uint32(calldata[96:100])
	if count != certCount {
		t.Errorf("expected count %d, got %d", certCount, count)
	}

	// 8. Differential assertion: production/manual anchorRoot calldata == go-ethereum accounts/abi Pack output
	const anchorRootABIJSON = `[{"type":"function","name":"anchorRoot","inputs":[{"name":"root","type":"bytes32"},{"name":"canonicalBatchID","type":"bytes32"},{"name":"certificateCount","type":"uint32"}],"outputs":[]}]`
	parsedABI, err := abi.JSON(strings.NewReader(anchorRootABIJSON))
	if err != nil {
		t.Fatalf("failed to parse ABI JSON: %v", err)
	}
	if !bytes.Equal(parsedABI.Methods["anchorRoot"].ID, expectedSelector[:]) {
		t.Fatalf("abi.Pack selector mismatch: expected %x, got %x", expectedSelector, parsedABI.Methods["anchorRoot"].ID)
	}
	abiPacked, err := parsedABI.Pack("anchorRoot", root, batchID, certCount)
	if err != nil {
		t.Fatalf("abi.Pack failed: %v", err)
	}
	if len(abiPacked) != 100 {
		t.Fatalf("expected abi.Pack output length 100, got %d", len(abiPacked))
	}
	if !bytes.Equal(calldata, abiPacked) {
		t.Fatalf("differential assertion failed: manual calldata != abi.Pack output\nmanual: %x\npacked: %x", calldata, abiPacked)
	}
}

// Fixed-vector provenance:
// The expected raw signed hex and transaction hash constants below were produced independently
// using ethers.js v6 (ethers.Wallet.signTransaction) and verified against standard EIP-1559 and
// RFC 6979 deterministic secp256k1 ECDSA signing rules. They were NOT calculated through the
// production Go signer under test.
func TestDeterministicSigner_AuthoritativeEthersVectors(t *testing.T) {
	anvil0PrivKey := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	anvil0Addr := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

	signer, err := NewDeterministicSigner(anvil0Addr, 80002, anvil0PrivKey)
	if err != nil {
		t.Fatalf("failed to create signer with Anvil 0: %v", err)
	}

	// Vector 1: Empty data
	tx1 := &UnsignedTx{
		ChainID:              big.NewInt(80002),
		Nonce:                0,
		MaxPriorityFeePerGas: big.NewInt(1500000000),  // 1.5 gwei
		MaxFeePerGas:         big.NewInt(30000000000), // 30 gwei
		GasLimit:             150000,
		To:                   "0x5FbDB2315678afecb367f032d93F642f64180aa3",
		Value:                big.NewInt(0),
		Data:                 []byte{},
	}

	rawHex1, txHash1, err := signer.SignTransaction(tx1)
	if err != nil {
		t.Fatalf("tx1 sign failed: %v", err)
	}

	const expectedRaw1 = "0x02f86f83013882808459682f008506fc23ac00830249f0945fbdb2315678afecb367f032d93f642f64180aa38080c001a0e28de2caed02699b23305d96e80c8c095a747bd8080bee651d1d50887e7c23d9a038f0d20132593317f4a3a76026834b2a758523b8fd8b70eacf0ac4a260e7e944"
	const expectedHash1 = "0xfe43501e7ae409b2ee8f1ed145c238bfd921de149005f1f7237ef6c69565dfcb"

	if rawHex1 != expectedRaw1 {
		t.Errorf("tx1 raw hex mismatch:\nexpected: %s\ngot:      %s", expectedRaw1, rawHex1)
	}
	if txHash1 != expectedHash1 {
		t.Errorf("tx1 hash mismatch:\nexpected: %s\ngot:      %s", expectedHash1, txHash1)
	}

	// Verify recovered sender matches Anvil 0
	rawBytes1, _ := hex.DecodeString(strings.TrimPrefix(rawHex1, "0x"))
	var decodedTx1 types.Transaction
	if err := decodedTx1.UnmarshalBinary(rawBytes1); err != nil {
		t.Fatalf("failed to unmarshal binary tx1: %v", err)
	}
	recoveredSender1, err := types.Sender(types.NewLondonSigner(big.NewInt(80002)), &decodedTx1)
	if err != nil {
		t.Fatalf("failed to recover sender for tx1: %v", err)
	}
	if recoveredSender1.Hex() != anvil0Addr {
		t.Errorf("recovered sender mismatch: expected %s, got %s", anvil0Addr, recoveredSender1.Hex())
	}

	// Vector 2: With canonical anchorRoot calldata (selector 0x9f4d6d5d, 100 bytes length)
	var root2 [32]byte
	var batchID2 [32]byte
	for i := range root2 {
		root2[i] = 0x11
		batchID2[i] = 0x22
	}
	const certCount2 = uint32(5)
	calldata2 := EncodeAnchorRootCalldata(root2, batchID2, certCount2)

	if len(calldata2) != 100 {
		t.Fatalf("expected calldata2 length 100, got %d", len(calldata2))
	}
	if !bytes.Equal(calldata2[:4], []byte{0x9f, 0x4d, 0x6d, 0x5d}) {
		t.Fatalf("calldata2 selector mismatch: expected 0x9f4d6d5d, got %x", calldata2[:4])
	}

	tx2 := &UnsignedTx{
		ChainID:              big.NewInt(80002),
		Nonce:                7,
		MaxPriorityFeePerGas: big.NewInt(2000000000),  // 2 gwei
		MaxFeePerGas:         big.NewInt(40000000000), // 40 gwei
		GasLimit:             180000,
		To:                   "0x5FbDB2315678afecb367f032d93F642f64180aa3",
		Value:                big.NewInt(0),
		Data:                 calldata2,
	}

	rawHex2, txHash2, err := signer.SignTransaction(tx2)
	if err != nil {
		t.Fatalf("tx2 sign failed: %v", err)
	}

	const expectedRaw2 = "0x02f8d4830138820784773594008509502f90008302bf20945fbdb2315678afecb367f032d93f642f64180aa380b8649f4d6d5d111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000005c080a0b0c64fba8757974c198edd454379cf6012e06d9759e90dab5caf74ba0ace3fa3a02758c537ff848a20b9923c1f0aa58aa5e0a962e8f64e6a01a00d956c19e948bf"
	const expectedHash2 = "0x52af552bec6881a713ec48e9f25c45ba5ec655db8b2d566d3ff1bd9da1cbb499"

	if rawHex2 != expectedRaw2 {
		t.Errorf("tx2 raw hex mismatch:\nexpected: %s\ngot:      %s", expectedRaw2, rawHex2)
	}
	if txHash2 != expectedHash2 {
		t.Errorf("tx2 hash mismatch:\nexpected: %s\ngot:      %s", expectedHash2, txHash2)
	}

	// Verify recovered sender matches Anvil 0
	rawBytes2, _ := hex.DecodeString(strings.TrimPrefix(rawHex2, "0x"))
	var decodedTx2 types.Transaction
	if err := decodedTx2.UnmarshalBinary(rawBytes2); err != nil {
		t.Fatalf("failed to unmarshal binary tx2: %v", err)
	}
	recoveredSender2, err := types.Sender(types.NewLondonSigner(big.NewInt(80002)), &decodedTx2)
	if err != nil {
		t.Fatalf("failed to recover sender for tx2: %v", err)
	}
	if recoveredSender2.Hex() != anvil0Addr {
		t.Errorf("recovered sender mismatch: expected %s, got %s", anvil0Addr, recoveredSender2.Hex())
	}

	// Deterministic repeated signing check
	rawHex2Again, txHash2Again, err := signer.SignTransaction(tx2)
	if err != nil {
		t.Fatalf("second sign failed: %v", err)
	}
	if rawHex2Again != rawHex2 || txHash2Again != txHash2 {
		t.Errorf("deterministic repeated signing failed: outputs differ across calls")
	}
}

func TestDeterministicSigner_KeyAndAddressValidation(t *testing.T) {
	validKey := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	validAddr := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

	// 1. Zero key
	zeroKey := strings.Repeat("0", 64)
	if _, err := NewDeterministicSigner(validAddr, 80002, zeroKey); err == nil {
		t.Errorf("expected error for zero private key")
	}

	// 2. Malformed key (short)
	if _, err := NewDeterministicSigner(validAddr, 80002, "12345"); err == nil {
		t.Errorf("expected error for short private key")
	}

	// 3. Malformed key (non-hex)
	nonHexKey := strings.Repeat("z", 64)
	if _, err := NewDeterministicSigner(validAddr, 80002, nonHexKey); err == nil {
		t.Errorf("expected error for non-hex private key")
	}

	// 4. Out-of-range key (private key scalar d >= secp256k1 curve order N)
	// Note: The private key scalar is d (1 <= d < N), while k is the per-signature nonce.
	// secp256k1 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
	secpOrderNKey := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
	if _, err := NewDeterministicSigner(validAddr, 80002, secpOrderNKey); err == nil {
		t.Errorf("expected error for out-of-range private key scalar d >= N")
	}

	// 5. Configured address / key mismatch
	mismatchAddr := "0x5FbDB2315678afecb367f032d93F642f64180aa3"
	if _, err := NewDeterministicSigner(mismatchAddr, 80002, validKey); err == nil {
		t.Errorf("expected error for address/key mismatch")
	}

	// 6. Malformed signer address (missing 0x prefix)
	if _, err := NewDeterministicSigner("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266", 80002, validKey); err == nil {
		t.Errorf("expected error for address missing 0x")
	}

	// 7. Malformed signer address (uppercase 0X prefix)
	if _, err := NewDeterministicSigner("0Xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", 80002, validKey); err == nil {
		t.Errorf("expected error for uppercase 0X address")
	}

	// 8. Malformed signer address (short length)
	if _, err := NewDeterministicSigner("0xf39Fd6", 80002, validKey); err == nil {
		t.Errorf("expected error for short address")
	}

	// 9. Malformed signer address (oversized length)
	if _, err := NewDeterministicSigner("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb9226600", 80002, validKey); err == nil {
		t.Errorf("expected error for oversized address")
	}
}

func TestDeterministicSigner_DestinationAddressValidation(t *testing.T) {
	anvil0PrivKey := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	anvil0Addr := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

	signer, err := NewDeterministicSigner(anvil0Addr, 80002, anvil0PrivKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	baseTx := func() *UnsignedTx {
		return &UnsignedTx{
			ChainID:              big.NewInt(80002),
			Nonce:                0,
			MaxPriorityFeePerGas: big.NewInt(1500000000),
			MaxFeePerGas:         big.NewInt(30000000000),
			GasLimit:             150000,
			To:                   "0x5FbDB2315678afecb367f032d93F642f64180aa3",
			Value:                big.NewInt(0),
			Data:                 []byte{},
		}
	}

	// Empty destination (must never be permitted to become contract creation)
	tx := baseTx()
	tx.To = ""
	if _, _, err := signer.SignTransaction(tx); err == nil {
		t.Errorf("expected error for empty destination address")
	}

	// Short destination
	tx = baseTx()
	tx.To = "0x1234"
	if _, _, err := signer.SignTransaction(tx); err == nil {
		t.Errorf("expected error for short destination address")
	}

	// Oversized destination
	tx = baseTx()
	tx.To = "0x5FbDB2315678afecb367f032d93F642f64180aa300"
	if _, _, err := signer.SignTransaction(tx); err == nil {
		t.Errorf("expected error for oversized destination address")
	}

	// Uppercase 0X
	tx = baseTx()
	tx.To = "0X5FbDB2315678afecb367f032d93F642f64180aa3"
	if _, _, err := signer.SignTransaction(tx); err == nil {
		t.Errorf("expected error for uppercase 0X destination address")
	}

	// Non-hex destination
	tx = baseTx()
	tx.To = "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
	if _, _, err := signer.SignTransaction(tx); err == nil {
		t.Errorf("expected error for non-hex destination address")
	}
}

func TestParseAndValidateRootAnchoredEvent_StrictRules(t *testing.T) {
	contractAddr := "0x5FbDB2315678afecb367f032d93F642f64180aa3"
	submitter := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

	var root [32]byte
	var batchID [32]byte
	root[0] = 0xaa
	batchID[0] = 0xbb

	makeValidReceipt := func() *Receipt {
		data := make([]byte, 64)
		binary.BigEndian.PutUint32(data[28:32], 10)
		binary.BigEndian.PutUint64(data[56:64], uint64(time.Now().Unix()))

		submitterClean := strings.TrimPrefix(submitter, "0x")
		submitterTopic := "0x" + strings.Repeat("0", 24) + submitterClean

		log := Log{
			Address: contractAddr,
			Topics: []string{
				"0x" + hex.EncodeToString(TopicRootAnchored[:]),
				"0x" + hex.EncodeToString(root[:]),
				"0x" + hex.EncodeToString(batchID[:]),
				submitterTopic,
			},
			Data:        data,
			BlockNumber: 50,
			TxHash:      "0x9999999999999999999999999999999999999999999999999999999999999999",
			Index:       0,
		}

		return &Receipt{
			TxHash:          log.TxHash,
			Status:          1,
			BlockNumber:     50,
			BlockHash:       "0xblockhash50",
			GasUsed:         75000,
			Logs:            []Log{log},
			ContractAddress: contractAddr,
		}
	}

	// 1. Success case
	r := makeValidReceipt()
	evt, err := ParseAndValidateRootAnchoredEvent(r, contractAddr, root, batchID, submitter, 10)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if evt.CertificateCount != 10 {
		t.Errorf("expected count 10, got %d", evt.CertificateCount)
	}

	// 2. Non-indexed data length != 64 (short data 63 bytes)
	r = makeValidReceipt()
	r.Logs[0].Data = make([]byte, 63)
	if _, err := ParseAndValidateRootAnchoredEvent(r, contractAddr, root, batchID, submitter, 10); err == nil {
		t.Errorf("expected error for data length 63 bytes")
	}

	// 3. Non-indexed data length != 64 (long data 65 bytes)
	r = makeValidReceipt()
	r.Logs[0].Data = make([]byte, 65)
	if _, err := ParseAndValidateRootAnchoredEvent(r, contractAddr, root, batchID, submitter, 10); err == nil {
		t.Errorf("expected error for data length 65 bytes")
	}

	// 4. Word 0 (uint32) non-zero in upper 28 bytes
	r = makeValidReceipt()
	r.Logs[0].Data[0] = 0x01
	if _, err := ParseAndValidateRootAnchoredEvent(r, contractAddr, root, batchID, submitter, 10); err == nil {
		t.Errorf("expected error for non-zero uint32 padding")
	}

	// 5. Word 1 (uint64) non-zero in upper 24 bytes
	r = makeValidReceipt()
	r.Logs[0].Data[32] = 0x01
	if _, err := ParseAndValidateRootAnchoredEvent(r, contractAddr, root, batchID, submitter, 10); err == nil {
		t.Errorf("expected error for non-zero uint64 padding")
	}

	// 6. Topic length != 66
	r = makeValidReceipt()
	r.Logs[0].Topics[1] = "0x1234"
	if _, err := ParseAndValidateRootAnchoredEvent(r, contractAddr, root, batchID, submitter, 10); err == nil {
		t.Errorf("expected error for short topic length")
	}

	// 7. Topic uppercase 0X prefix
	r = makeValidReceipt()
	r.Logs[0].Topics[1] = "0X" + hex.EncodeToString(root[:])
	if _, err := ParseAndValidateRootAnchoredEvent(r, contractAddr, root, batchID, submitter, 10); err == nil {
		t.Errorf("expected error for uppercase 0X topic prefix")
	}

	// 8. Indexed submitter first 12 raw bytes non-zero
	r = makeValidReceipt()
	corruptedSubmitter := "0x010000000000000000000000" + strings.TrimPrefix(submitter, "0x")
	r.Logs[0].Topics[3] = corruptedSubmitter
	if _, err := ParseAndValidateRootAnchoredEvent(r, contractAddr, root, batchID, submitter, 10); err == nil {
		t.Errorf("expected error for non-zero first 12 bytes of submitter topic")
	}

	// 9. Submitter address mismatch
	r = makeValidReceipt()
	wrongSubmitter := "0x0000000000000000000000000000000000000001"
	if _, err := ParseAndValidateRootAnchoredEvent(r, contractAddr, root, batchID, wrongSubmitter, 10); err == nil {
		t.Errorf("expected error for submitter mismatch")
	}
}

func TestMockBlockchainClient(t *testing.T) {
	mock := NewMockBlockchainClient()
	ctx := context.Background()

	// Nonce
	nonce, err := mock.GetPendingNonce(ctx, "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c")
	if err != nil || nonce != 0 {
		t.Errorf("expected nonce 0, got %d (err: %v)", nonce, err)
	}

	// Gas
	gas, err := mock.EstimateGas(ctx, CallMsg{To: "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c"})
	if err != nil || gas != 150000 {
		t.Errorf("expected gas 150000, got %d", gas)
	}

	// FeeData
	fee, err := mock.GetFeeData(ctx)
	if err != nil || fee == nil || fee.BaseFee.Int64() != 1000000000 {
		t.Errorf("unexpected fee data: %v", fee)
	}

	// Broadcast
	hash, err := mock.BroadcastTransaction(ctx, "0x021234")
	if err != nil || !strings.HasPrefix(hash, "0x") {
		t.Errorf("unexpected broadcast result: %s, %v", hash, err)
	}
	if len(mock.BroadcastedTxs) != 1 {
		t.Errorf("expected 1 broadcasted tx, got %d", len(mock.BroadcastedTxs))
	}

	// Block height
	height, err := mock.GetBlockHeight(ctx)
	if err != nil || height != 100 {
		t.Errorf("expected height 100, got %d", height)
	}

	// Chain ID
	chainID, err := mock.GetChainID(ctx)
	if err != nil || chainID != 80002 {
		t.Errorf("expected chain ID 80002, got %d (err: %v)", chainID, err)
	}

	// Code
	contractAddr := "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c"
	code, err := mock.GetCode(ctx, contractAddr)
	if err != nil || len(code) != 0 {
		t.Errorf("expected empty code initially, got %v (err: %v)", code, err)
	}
	mock.SetCode(contractAddr, []byte{0x60, 0x80})
	code, err = mock.GetCode(ctx, contractAddr)
	if err != nil || len(code) != 2 {
		t.Errorf("expected 2 bytes code, got %v", code)
	}

	// IsAnchorer
	accountAddr := "0x2222222222222222222222222222222222222222"
	isAuth, err := mock.IsAnchorer(ctx, contractAddr, accountAddr)
	if err != nil || isAuth {
		t.Errorf("expected false initially, got %v (err: %v)", isAuth, err)
	}
	mock.SetAnchorer(contractAddr, accountAddr, true)
	isAuth, err = mock.IsAnchorer(ctx, contractAddr, accountAddr)
	if err != nil || !isAuth {
		t.Errorf("expected true after set, got %v (err: %v)", isAuth, err)
	}
}

func TestRPCClient_GetChainID(t *testing.T) {
	// 1. Valid chain ID (Polygon Amoy 80002 -> 0x13882)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method != "eth_chainId" {
			t.Errorf("unexpected method: %s", req.Method)
		}
		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  json.RawMessage(`"0x13882"`),
		})
	}))
	defer srv.Close()

	client := NewRPCClient(srv.URL, 2*time.Second)
	chainID, err := client.GetChainID(context.Background())
	if err != nil {
		t.Fatalf("expected successful GetChainID, got: %v", err)
	}
	if chainID != 80002 {
		t.Errorf("expected chain ID 80002, got %d", chainID)
	}

	// 2. RPC Error response
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Error:   &jsonRPCError{Code: -32000, Message: "node syncing"},
		})
	}))
	defer errSrv.Close()

	errClient := NewRPCClient(errSrv.URL, 2*time.Second)
	if _, err := errClient.GetChainID(context.Background()); err == nil {
		t.Errorf("expected error from RPC error response")
	}

	// 3. Malformed hex
	badHexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Result:  json.RawMessage(`"0xZZZZ"`),
		})
	}))
	defer badHexSrv.Close()

	badClient := NewRPCClient(badHexSrv.URL, 2*time.Second)
	if _, err := badClient.GetChainID(context.Background()); err == nil {
		t.Errorf("expected error from malformed hex")
	}

	// 4. Null response
	nullSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Result:  json.RawMessage(`null`),
		})
	}))
	defer nullSrv.Close()

	nullClient := NewRPCClient(nullSrv.URL, 2*time.Second)
	if _, err := nullClient.GetChainID(context.Background()); err == nil {
		t.Errorf("expected error from null response")
	}

	// 5. Context timeout / cancellation
	hangSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer hangSrv.Close()

	hangClient := NewRPCClient(hangSrv.URL, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := hangClient.GetChainID(ctx); err == nil {
		t.Errorf("expected error from timed out context")
	}
}

func TestRPCClient_GetCode(t *testing.T) {
	contractAddr := "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c"

	// 1. Success with valid bytecode
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method != "eth_getCode" {
			t.Errorf("unexpected method: %s", req.Method)
		}
		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  json.RawMessage(`"0x6080604052348015"`),
		})
	}))
	defer srv.Close()

	client := NewRPCClient(srv.URL, 2*time.Second)
	code, err := client.GetCode(context.Background(), contractAddr)
	if err != nil {
		t.Fatalf("expected successful GetCode, got: %v", err)
	}
	expectedCode, _ := hex.DecodeString("6080604052348015")
	if !bytes.Equal(code, expectedCode) {
		t.Errorf("code mismatch: expected %x, got %x", expectedCode, code)
	}

	// 2. Empty code ("0x")
	emptySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Result:  json.RawMessage(`"0x"`),
		})
	}))
	defer emptySrv.Close()

	emptyClient := NewRPCClient(emptySrv.URL, 2*time.Second)
	emptyCode, err := emptyClient.GetCode(context.Background(), contractAddr)
	if err != nil {
		t.Fatalf("expected success for 0x, got: %v", err)
	}
	if len(emptyCode) != 0 {
		t.Errorf("expected 0 bytes for empty code, got %d", len(emptyCode))
	}

	// 3. Invalid address format
	if _, err := client.GetCode(context.Background(), "invalid-addr"); err == nil {
		t.Errorf("expected error for invalid address")
	}

	// 4. Malformed hex
	badHexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Result:  json.RawMessage(`"0xnothex"`),
		})
	}))
	defer badHexSrv.Close()

	badHexClient := NewRPCClient(badHexSrv.URL, 2*time.Second)
	if _, err := badHexClient.GetCode(context.Background(), contractAddr); err == nil {
		t.Errorf("expected error for malformed hex bytecode")
	}
}

func TestRPCClient_IsAnchorer(t *testing.T) {
	contractAddr := "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c"
	accountAddr := "0x2222222222222222222222222222222222222222"

	// 1. Success true
	srvTrue := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method != "eth_call" {
			t.Errorf("unexpected method: %s", req.Method)
		}
		// Verify payload data
		params, _ := req.Params[0].(map[string]interface{})
		to, _ := params["to"].(string)
		if !strings.EqualFold(to, contractAddr) {
			t.Errorf("unexpected target address: %s", to)
		}
		data, _ := params["data"].(string)
		expectedCalldata := "0x" + hex.EncodeToString(EncodeIsAnchorerCalldata(common.HexToAddress(accountAddr)))
		if data != expectedCalldata {
			t.Errorf("unexpected calldata: got %s, expected %s", data, expectedCalldata)
		}

		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  json.RawMessage(`"0x0000000000000000000000000000000000000000000000000000000000000001"`),
		})
	}))
	defer srvTrue.Close()

	client := NewRPCClient(srvTrue.URL, 2*time.Second)
	isAuth, err := client.IsAnchorer(context.Background(), contractAddr, accountAddr)
	if err != nil {
		t.Fatalf("expected successful IsAnchorer, got: %v", err)
	}
	if !isAuth {
		t.Errorf("expected isAuth = true")
	}

	// 2. Success false
	srvFalse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Result:  json.RawMessage(`"0x0000000000000000000000000000000000000000000000000000000000000000"`),
		})
	}))
	defer srvFalse.Close()

	clientFalse := NewRPCClient(srvFalse.URL, 2*time.Second)
	isAuthFalse, err := clientFalse.IsAnchorer(context.Background(), contractAddr, accountAddr)
	if err != nil {
		t.Fatalf("expected successful IsAnchorer, got: %v", err)
	}
	if isAuthFalse {
		t.Errorf("expected isAuth = false")
	}

	// 3. Strict ABI decoding: non-zero byte in padding
	srvBadPadding := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Result:  json.RawMessage(`"0x0100000000000000000000000000000000000000000000000000000000000001"`),
		})
	}))
	defer srvBadPadding.Close()

	clientBadPadding := NewRPCClient(srvBadPadding.URL, 2*time.Second)
	if _, err := clientBadPadding.IsAnchorer(context.Background(), contractAddr, accountAddr); err == nil {
		t.Errorf("expected error for non-zero padding in boolean ABI")
	}

	// 4. Invalid boolean value (e.g. 2 in last byte)
	srvInvalidVal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Result:  json.RawMessage(`"0x0000000000000000000000000000000000000000000000000000000000000002"`),
		})
	}))
	defer srvInvalidVal.Close()

	clientInvalidVal := NewRPCClient(srvInvalidVal.URL, 2*time.Second)
	if _, err := clientInvalidVal.IsAnchorer(context.Background(), contractAddr, accountAddr); err == nil {
		t.Errorf("expected error for invalid boolean value 2")
	}

	// 5. Malformed response length
	srvShort := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Result:  json.RawMessage(`"0x01"`),
		})
	}))
	defer srvShort.Close()

	clientShort := NewRPCClient(srvShort.URL, 2*time.Second)
	if _, err := clientShort.IsAnchorer(context.Background(), contractAddr, accountAddr); err == nil {
		t.Errorf("expected error for short response length")
	}

	// 6. Invalid contract or account address format
	if _, err := client.IsAnchorer(context.Background(), "invalid-contract", accountAddr); err == nil {
		t.Errorf("expected error for invalid contract address")
	}
	if _, err := client.IsAnchorer(context.Background(), contractAddr, "invalid-account"); err == nil {
		t.Errorf("expected error for invalid account address")
	}
}

func TestSanitizeRPCURL(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{
			input:    "https://user:password@amoy.polygon.technology/v1/rpc",
			expected: "https://%5BREDACTED%5D@amoy.polygon.technology/v1/rpc",
		},
		{
			input:    "https://amoy.polygon.technology/rpc?apiKey=supersecret&token=abc",
			expected: "https://amoy.polygon.technology/rpc?apiKey=%5BREDACTED%5D&token=%5BREDACTED%5D",
		},
		{
			input:    "https://rpc-amoy.polygon.technology",
			expected: "https://rpc-amoy.polygon.technology",
		},
		{
			input:    "",
			expected: "",
		},
		{
			input:    "://invalid-url",
			expected: "[MALFORMED_URL]",
		},
	}

	for _, tc := range cases {
		actual := SanitizeRPCURL(tc.input)
		if actual != tc.expected {
			t.Errorf("SanitizeRPCURL(%q): expected %q, got %q", tc.input, tc.expected, actual)
		}
	}
}

// Ensure common.Address is referenced so compiler does not complain if unused.
var _ = common.Address{}
