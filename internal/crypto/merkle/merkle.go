package merkle

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/sha3"
)

const (
	// AlgorithmTDKeccak256V1 is the approved Merkle tree algorithm identifier.
	AlgorithmTDKeccak256V1 = "TD-MERKLE-KECCAK256-V1"

	// TreeVersion1 is the integer version of the Merkle tree construction.
	TreeVersion1 = 1

	// LeafEncodingTDLeafV1 is the leaf encoding format version.
	LeafEncodingTDLeafV1 = "TD-LEAF-V1"

	// ProofFormatTDSortedV1 is the proof ordering format version.
	ProofFormatTDSortedV1 = "TD-PROOF-SORTED-V1"

	// CanonicalBatchIDPrefix is the domain-separated prefix for batch IDs.
	CanonicalBatchIDPrefix = "trustdocs:batch:v1:"

	// MaxProofDepth is the maximum allowed sibling depth (supports up to 2^20 leaves).
	MaxProofDepth = 20

	// LeafDomainSeparator is the single byte prefix (0x00) for leaf preimage hashing.
	LeafDomainSeparator byte = 0x00

	// InternalDomainSeparator is the single byte prefix (0x01) for internal node preimage hashing.
	InternalDomainSeparator byte = 0x01
)

var (
	// publicIDRegex enforces the exact format: ^TD-CERT-[A-Z0-9]{16,32}$
	publicIDRegex = regexp.MustCompile(`^TD-CERT-[A-Z0-9]{16,32}$`)

	// hex64Regex enforces 64 lowercase hexadecimal characters.
	hex64Regex = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// CertificateLeafInput holds the raw attributes required to derive a leaf node.
type CertificateLeafInput struct {
	CertificateID string // Optional database UUID or tracking reference
	PublicID      string // Must match ^TD-CERT-[A-Z0-9]{16,32}$
	DocumentHash  string // 64 lowercase hex characters (SHA-256 document hash)
}

// LeafRecord represents a positioned leaf with its preimages, sorted index, and proof.
type LeafRecord struct {
	CertificateID string     `json:"certificate_id,omitempty"`
	PublicID      string     `json:"public_id"`
	DocumentHash  string     `json:"document_hash"`
	LeafHash      [32]byte   `json:"-"`
	LeafHashHex   string     `json:"leaf_hash"`
	LeafIndex     int        `json:"leaf_index"`
	Proof         [][32]byte `json:"-"`
	ProofHex      []string   `json:"proof"`
}

// MerkleTree contains the finalized root, leaves, and cryptographic specification metadata.
type MerkleTree struct {
	Algorithm           string       `json:"tree_algorithm"`
	TreeVersion         int          `json:"tree_version"`
	LeafEncodingVersion string       `json:"leaf_encoding_version"`
	ProofFormatVersion  string       `json:"proof_format_version"`
	Root                [32]byte     `json:"-"`
	RootHex             string       `json:"merkle_root"`
	Leaves              []LeafRecord `json:"leaves"`
}

// DeriveCanonicalBatchID derives the bytes32 canonical batch ID:
//
//	Keccak256("trustdocs:batch:v1:" || raw_16_byte_batch_uuid)
//
// returning "0x" + 64 lowercase hexadecimal characters.
func DeriveCanonicalBatchID(batchUUID string) (string, error) {
	clean := strings.TrimSpace(batchUUID)
	hexStr := strings.ToLower(strings.ReplaceAll(clean, "-", ""))
	if len(hexStr) != 32 {
		return "", fmt.Errorf("invalid UUID string length for canonical batch ID: %q (expected 32 hex chars)", batchUUID)
	}

	rawUUID, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", fmt.Errorf("invalid hexadecimal characters in UUID %q: %w", batchUUID, err)
	}

	var uuidBytes [16]byte
	copy(uuidBytes[:], rawUUID)
	return DeriveCanonicalBatchIDFromBytes(uuidBytes), nil
}

// DeriveCanonicalBatchIDFromBytes computes the canonical batch ID from raw 16 UUID bytes.
func DeriveCanonicalBatchIDFromBytes(uuidBytes [16]byte) string {
	buf := make([]byte, len(CanonicalBatchIDPrefix)+16)
	copy(buf[:len(CanonicalBatchIDPrefix)], CanonicalBatchIDPrefix)
	copy(buf[len(CanonicalBatchIDPrefix):], uuidBytes[:])

	h := sha3.NewLegacyKeccak256()
	h.Write(buf)
	sum := h.Sum(nil)

	return "0x" + hex.EncodeToString(sum)
}

// ParseDocumentHash parses and validates a 32-byte (64 hex characters) SHA-256 document hash.
func ParseDocumentHash(docHash string) ([32]byte, error) {
	clean := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(docHash, "0x")))
	if !hex64Regex.MatchString(clean) {
		return [32]byte{}, fmt.Errorf("document hash must be 64 lowercase hex characters, got length %d (%q)", len(clean), docHash)
	}

	raw, err := hex.DecodeString(clean)
	if err != nil {
		return [32]byte{}, fmt.Errorf("invalid hex in document hash: %w", err)
	}

	var out [32]byte
	copy(out[:], raw)
	return out, nil
}

// DeriveLeafHash computes the TD-LEAF-V1 leaf hash:
//
//	Keccak256(
//	    0x00 ||
//	    uint16_be(len(public_id)) ||
//	    ASCII(public_id) ||
//	    raw_32_byte_SHA256_document_hash
//	)
func DeriveLeafHash(publicID string, documentHash string) ([32]byte, string, error) {
	pid := strings.TrimSpace(publicID)
	if !publicIDRegex.MatchString(pid) {
		return [32]byte{}, "", fmt.Errorf("invalid public ID format %q; must match ^TD-CERT-[A-Z0-9]{16,32}$", publicID)
	}

	rawDocHash, err := ParseDocumentHash(documentHash)
	if err != nil {
		return [32]byte{}, "", fmt.Errorf("invalid document hash for %s: %w", publicID, err)
	}

	pidBytes := []byte(pid)
	if len(pidBytes) > 65535 {
		return [32]byte{}, "", errors.New("public ID byte length exceeds uint16 max")
	}

	buf := make([]byte, 1+2+len(pidBytes)+32)
	buf[0] = LeafDomainSeparator
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(pidBytes)))
	copy(buf[3:3+len(pidBytes)], pidBytes)
	copy(buf[3+len(pidBytes):], rawDocHash[:])

	h := sha3.NewLegacyKeccak256()
	h.Write(buf)
	var leafHash [32]byte
	copy(leafHash[:], h.Sum(nil))

	return leafHash, "0x" + hex.EncodeToString(leafHash[:]), nil
}

// HashInternal computes the sorted internal node hash:
//
//	Keccak256(0x01 || min(left, right) || max(left, right))
//
// where min and max are determined by standard 32-byte lexicographical comparison.
func HashInternal(left, right [32]byte) [32]byte {
	first, second := left, right
	if bytes.Compare(left[:], right[:]) > 0 {
		first, second = right, left
	}

	buf := make([]byte, 1+32+32)
	buf[0] = InternalDomainSeparator
	copy(buf[1:33], first[:])
	copy(buf[33:65], second[:])

	h := sha3.NewLegacyKeccak256()
	h.Write(buf)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// BuildTree constructs a deterministic TD-MERKLE-KECCAK256-V1 Merkle tree:
// 1. Derives each leaf hash with domain separation (0x00).
// 2. Rejects duplicate inputs or duplicate leaf hashes.
// 3. Sorts leaves lexicographically by 32-byte leaf hash.
// 4. Builds levels bottom-to-top with 0x01 internal node domain separation.
// 5. Promotes unpaired odd nodes without duplicating them.
// 6. Generates inclusion proofs ordered bottom-to-top.
func BuildTree(inputs []CertificateLeafInput) (*MerkleTree, error) {
	if len(inputs) == 0 {
		return nil, errors.New("cannot build Merkle tree from empty inputs")
	}

	leaves := make([]LeafRecord, len(inputs))
	seenLeafHashes := make(map[[32]byte]string, len(inputs))

	for i, in := range inputs {
		leafHash, leafHex, err := DeriveLeafHash(in.PublicID, in.DocumentHash)
		if err != nil {
			return nil, fmt.Errorf("failed to derive leaf hash for input [%d] (public_id=%q): %w", i, in.PublicID, err)
		}

		if existingPID, exists := seenLeafHashes[leafHash]; exists {
			return nil, fmt.Errorf("duplicate leaf hash detected: public_id %q collides with %q (hash=%s)",
				in.PublicID, existingPID, leafHex)
		}
		seenLeafHashes[leafHash] = in.PublicID

		cleanDocHash := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(in.DocumentHash, "0x")))

		leaves[i] = LeafRecord{
			CertificateID: in.CertificateID,
			PublicID:      strings.TrimSpace(in.PublicID),
			DocumentHash:  cleanDocHash,
			LeafHash:      leafHash,
			LeafHashHex:   leafHex,
		}
	}

	// Lexicographically sort leaves by their 32-byte leaf hash
	sort.Slice(leaves, func(i, j int) bool {
		return bytes.Compare(leaves[i].LeafHash[:], leaves[j].LeafHash[:]) < 0
	})

	for i := range leaves {
		leaves[i].LeafIndex = i
		leaves[i].Proof = make([][32]byte, 0)
	}

	// Base case: single leaf tree
	if len(leaves) == 1 {
		leaves[0].ProofHex = []string{}
		return &MerkleTree{
			Algorithm:           AlgorithmTDKeccak256V1,
			TreeVersion:         TreeVersion1,
			LeafEncodingVersion: LeafEncodingTDLeafV1,
			ProofFormatVersion:  ProofFormatTDSortedV1,
			Root:                leaves[0].LeafHash,
			RootHex:             leaves[0].LeafHashHex,
			Leaves:              leaves,
		}, nil
	}

	numLeaves := len(leaves)
	currentLevel := make([][32]byte, numLeaves)
	for i := 0; i < numLeaves; i++ {
		currentLevel[i] = leaves[i].LeafHash
	}

	// leafPositions tracks each leaf's current position in currentLevel
	leafPositions := make([]int, numLeaves)
	for i := 0; i < numLeaves; i++ {
		leafPositions[i] = i
	}

	// Iteratively reduce level until single root remains
	for len(currentLevel) > 1 {
		nextLevelLen := (len(currentLevel) + 1) / 2
		nextLevel := make([][32]byte, nextLevelLen)
		nextLeafPositions := make([]int, numLeaves)

		pairs := len(currentLevel) / 2
		for p := 0; p < pairs; p++ {
			leftIdx := 2 * p
			rightIdx := 2*p + 1

			parent := HashInternal(currentLevel[leftIdx], currentLevel[rightIdx])
			nextLevel[p] = parent

			// Append sibling proof for any leaf currently at leftIdx or rightIdx
			for k := 0; k < numLeaves; k++ {
				if leafPositions[k] == leftIdx {
					leaves[k].Proof = append(leaves[k].Proof, currentLevel[rightIdx])
					nextLeafPositions[k] = p
				} else if leafPositions[k] == rightIdx {
					leaves[k].Proof = append(leaves[k].Proof, currentLevel[leftIdx])
					nextLeafPositions[k] = p
				}
			}
		}

		// Promote unpaired odd node without duplicating
		if len(currentLevel)%2 != 0 {
			oddIdx := len(currentLevel) - 1
			lastPos := nextLevelLen - 1
			nextLevel[lastPos] = currentLevel[oddIdx]

			for k := 0; k < numLeaves; k++ {
				if leafPositions[k] == oddIdx {
					// No sibling at this level: promoted directly
					nextLeafPositions[k] = lastPos
				}
			}
		}

		currentLevel = nextLevel
		leafPositions = nextLeafPositions
	}

	root := currentLevel[0]
	rootHex := "0x" + hex.EncodeToString(root[:])

	// Format proof nodes as lowercase hex and enforce depth bounds
	for i := range leaves {
		if len(leaves[i].Proof) > MaxProofDepth {
			return nil, fmt.Errorf("merkle proof depth %d for leaf %d exceeds maximum allowed %d",
				len(leaves[i].Proof), i, MaxProofDepth)
		}
		leaves[i].ProofHex = make([]string, len(leaves[i].Proof))
		for j, node := range leaves[i].Proof {
			leaves[i].ProofHex[j] = "0x" + hex.EncodeToString(node[:])
		}
	}

	return &MerkleTree{
		Algorithm:           AlgorithmTDKeccak256V1,
		TreeVersion:         TreeVersion1,
		LeafEncodingVersion: LeafEncodingTDLeafV1,
		ProofFormatVersion:  ProofFormatTDSortedV1,
		Root:                root,
		RootHex:             rootHex,
		Leaves:              leaves,
	}, nil
}

// VerifyProof verifies that leafHash is included under root using the provided sibling proof.
func VerifyProof(root [32]byte, leafHash [32]byte, proof [][32]byte) (bool, error) {
	if len(proof) > MaxProofDepth {
		return false, fmt.Errorf("proof depth %d exceeds maximum depth %d", len(proof), MaxProofDepth)
	}

	current := leafHash
	for _, sibling := range proof {
		current = HashInternal(current, sibling)
	}

	return current == root, nil
}

// VerifyProofHex validates and verifies hexadecimal root, leaf, and proof nodes.
func VerifyProofHex(rootHex string, leafHashHex string, proofHex []string) (bool, error) {
	root, err := ParseHex32(rootHex)
	if err != nil {
		return false, fmt.Errorf("invalid root hex %q: %w", rootHex, err)
	}

	leafHash, err := ParseHex32(leafHashHex)
	if err != nil {
		return false, fmt.Errorf("invalid leaf hash hex %q: %w", leafHashHex, err)
	}

	if len(proofHex) > MaxProofDepth {
		return false, fmt.Errorf("proof depth %d exceeds maximum depth %d", len(proofHex), MaxProofDepth)
	}

	proof := make([][32]byte, len(proofHex))
	for i, s := range proofHex {
		node, err := ParseHex32(s)
		if err != nil {
			return false, fmt.Errorf("invalid proof node hex at index %d (%q): %w", i, s, err)
		}
		proof[i] = node
	}

	return VerifyProof(root, leafHash, proof)
}

// ParseHex32 parses a 64-character lowercase hexadecimal string (with optional "0x" prefix) into [32]byte.
func ParseHex32(s string) ([32]byte, error) {
	clean := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(s, "0x")))
	if !hex64Regex.MatchString(clean) {
		return [32]byte{}, fmt.Errorf("expected 64 lowercase hexadecimal characters, got %d (%q)", len(clean), s)
	}

	raw, err := hex.DecodeString(clean)
	if err != nil {
		return [32]byte{}, err
	}

	var out [32]byte
	copy(out[:], raw)
	return out, nil
}
