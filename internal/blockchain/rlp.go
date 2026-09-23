package blockchain

import (
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
)

// NOTE ON RLP ENCODING UTILITIES:
// The helper functions in this file provide standard Ethereum RLP encoding utilities retained
// for differential unit testing and legacy auxiliary payload serialization.
// They are NOT used on consensus-sensitive transaction signing or hashing paths.
// All consensus transaction serialization, EIP-1559 payload encoding, signature generation,
// and transaction hash derivation are authoritatively performed by go-ethereum core/types.

// RLPEncodeBytes encodes a byte slice according to Ethereum RLP specification.
func RLPEncodeBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return []byte{b[0]}
	}
	if len(b) <= 55 {
		res := make([]byte, 1+len(b))
		res[0] = byte(0x80 + len(b))
		copy(res[1:], b)
		return res
	}

	lenBytes := intToBigEndianBytes(uint64(len(b)))
	res := make([]byte, 1+len(lenBytes)+len(b))
	res[0] = byte(0xb7 + len(lenBytes))
	copy(res[1:], lenBytes)
	copy(res[1+len(lenBytes):], b)
	return res
}

// RLPEncodeUint64 encodes a uint64 according to Ethereum RLP integer rules.
func RLPEncodeUint64(val uint64) []byte {
	if val == 0 {
		return []byte{0x80}
	}
	return RLPEncodeBytes(intToBigEndianBytes(val))
}

// RLPEncodeBigInt encodes a big.Int according to Ethereum RLP integer rules.
func RLPEncodeBigInt(val *big.Int) []byte {
	if val == nil || val.Sign() <= 0 {
		return []byte{0x80}
	}
	return RLPEncodeBytes(val.Bytes())
}

// RLPEncodeAddress encodes an Ethereum 20-byte address hex string.
func RLPEncodeAddress(addr string) []byte {
	clean := strings.TrimPrefix(strings.TrimSpace(addr), "0x")
	bytes, err := hex.DecodeString(clean)
	if err != nil || len(bytes) != 20 {
		// Return 20 zero bytes if invalid
		return RLPEncodeBytes(make([]byte, 20))
	}
	return RLPEncodeBytes(bytes)
}

// RLPEncodeList encodes a list of already-encoded RLP elements.
func RLPEncodeList(elements [][]byte) []byte {
	var totalLen int
	for _, el := range elements {
		totalLen += len(el)
	}

	var payload []byte
	payload = make([]byte, 0, totalLen)
	for _, el := range elements {
		payload = append(payload, el...)
	}

	if len(payload) <= 55 {
		res := make([]byte, 1+len(payload))
		res[0] = byte(0xc0 + len(payload))
		copy(res[1:], payload)
		return res
	}

	lenBytes := intToBigEndianBytes(uint64(len(payload)))
	res := make([]byte, 1+len(lenBytes)+len(payload))
	res[0] = byte(0xf7 + len(lenBytes))
	copy(res[1:], lenBytes)
	copy(res[1+len(lenBytes):], payload)
	return res
}

func intToBigEndianBytes(val uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], val)
	var start int
	for start = 0; start < 8; start++ {
		if buf[start] != 0 {
			break
		}
	}
	if start == 8 {
		return []byte{0}
	}
	return buf[start:]
}
