package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func TestBuildTree_EmptyInputs(t *testing.T) {
	_, err := BuildTree([]CertificateLeafInput{})
	if err == nil {
		t.Error("expected error when building tree from empty inputs, got nil")
	}
}

func TestBuildTree_SingleLeaf(t *testing.T) {
	docHash := fmt.Sprintf("%x", sha256.Sum256([]byte("doc-1")))
	input := []CertificateLeafInput{
		{
			CertificateID: "10000000-0000-0000-0000-000000000001",
			PublicID:      "TD-CERT-0000000000000001",
			DocumentHash:  docHash,
		},
	}

	tree, err := BuildTree(input)
	if err != nil {
		t.Fatalf("BuildTree error on single leaf: %v", err)
	}

	if tree.RootHex != tree.Leaves[0].LeafHashHex {
		t.Errorf("single leaf tree root should equal leaf hash: root=%s, leaf=%s",
			tree.RootHex, tree.Leaves[0].LeafHashHex)
	}
	if len(tree.Leaves[0].Proof) != 0 {
		t.Errorf("single leaf should have empty proof, got length %d", len(tree.Leaves[0].Proof))
	}

	// Verification of single leaf
	valid, err := VerifyProof(tree.Root, tree.Leaves[0].LeafHash, tree.Leaves[0].Proof)
	if err != nil {
		t.Fatalf("VerifyProof failed on single leaf: %v", err)
	}
	if !valid {
		t.Error("VerifyProof returned false on valid single leaf")
	}
}

func TestBuildTree_ShuffledOrderInvariance(t *testing.T) {
	// Generate 16 distinct certificates
	inputs := make([]CertificateLeafInput, 16)
	for i := 0; i < 16; i++ {
		docHash := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("doc-shuffled-%d", i))))
		inputs[i] = CertificateLeafInput{
			CertificateID: fmt.Sprintf("10000000-0000-0000-0000-0000000000%02d", i+1),
			PublicID:      fmt.Sprintf("TD-CERT-%016d", i+1),
			DocumentHash:  docHash,
		}
	}

	// Build original tree
	originalTree, err := BuildTree(inputs)
	if err != nil {
		t.Fatalf("BuildTree original failed: %v", err)
	}

	// Shuffle inputs using deterministic seed
	r := rand.New(rand.NewSource(42))
	for round := 0; round < 5; round++ {
		shuffled := make([]CertificateLeafInput, len(inputs))
		copy(shuffled, inputs)
		r.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})

		shuffledTree, err := BuildTree(shuffled)
		if err != nil {
			t.Fatalf("BuildTree shuffled round %d failed: %v", round, err)
		}

		// Root must be identical regardless of input ordering
		if shuffledTree.RootHex != originalTree.RootHex {
			t.Errorf("shuffled round %d root mismatch: got %s, expected %s",
				round, shuffledTree.RootHex, originalTree.RootHex)
		}

		// Each leaf must match in index and hash
		for i := range originalTree.Leaves {
			if shuffledTree.Leaves[i].LeafHashHex != originalTree.Leaves[i].LeafHashHex {
				t.Errorf("shuffled round %d leaf %d hash mismatch", round, i)
			}
			if shuffledTree.Leaves[i].PublicID != originalTree.Leaves[i].PublicID {
				t.Errorf("shuffled round %d leaf %d public_id mismatch", round, i)
			}
		}
	}
}

func TestBuildTree_DuplicateLeafRejection(t *testing.T) {
	docHash := fmt.Sprintf("%x", sha256.Sum256([]byte("duplicate-doc")))
	inputs := []CertificateLeafInput{
		{
			PublicID:     "TD-CERT-0000000000000001",
			DocumentHash: docHash,
		},
		{
			PublicID:     "TD-CERT-0000000000000001",
			DocumentHash: docHash,
		},
	}

	_, err := BuildTree(inputs)
	if err == nil {
		t.Error("expected error when building tree with duplicate leaves, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate leaf hash") {
		t.Errorf("expected duplicate leaf hash error message, got: %v", err)
	}
}

func TestDeriveLeafHash_Validation(t *testing.T) {
	validDocHash := fmt.Sprintf("%x", sha256.Sum256([]byte("test-doc")))

	testCases := []struct {
		name        string
		publicID    string
		docHash     string
		expectError bool
	}{
		{
			name:        "valid leaf",
			publicID:    "TD-CERT-1234567890ABCDEF",
			docHash:     validDocHash,
			expectError: false,
		},
		{
			name:        "valid leaf with 0x prefix on doc hash",
			publicID:    "TD-CERT-1234567890ABCDEF",
			docHash:     "0x" + validDocHash,
			expectError: false,
		},
		{
			name:        "invalid public ID missing prefix",
			publicID:    "CERT-1234567890ABCDEF",
			docHash:     validDocHash,
			expectError: true,
		},
		{
			name:        "invalid public ID lowercase letters",
			publicID:    "TD-CERT-1234567890abcdef",
			docHash:     validDocHash,
			expectError: true,
		},
		{
			name:        "invalid public ID too short",
			publicID:    "TD-CERT-12345",
			docHash:     validDocHash,
			expectError: true,
		},
		{
			name:        "invalid public ID too long",
			publicID:    "TD-CERT-" + strings.Repeat("A", 33),
			docHash:     validDocHash,
			expectError: true,
		},
		{
			name:        "invalid doc hash too short",
			publicID:    "TD-CERT-1234567890ABCDEF",
			docHash:     "abc123",
			expectError: true,
		},
		{
			name:        "invalid doc hash non-hex characters",
			publicID:    "TD-CERT-1234567890ABCDEF",
			docHash:     strings.Repeat("z", 64),
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, hexHash, err := DeriveLeafHash(tc.publicID, tc.docHash)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error for %s, got nil (hash=%s)", tc.name, hexHash)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for %s: %v", tc.name, err)
				}
				if !strings.HasPrefix(hexHash, "0x") || len(hexHash) != 66 {
					t.Errorf("expected 66 char 0x-prefixed hash, got %s", hexHash)
				}
			}
		})
	}
}

func TestDeriveCanonicalBatchID_Validation(t *testing.T) {
	testCases := []struct {
		name        string
		uuid        string
		expectError bool
	}{
		{
			name:        "standard hyphenated UUID",
			uuid:        "10000000-0000-0000-0000-000000000001",
			expectError: false,
		},
		{
			name:        "unhyphenated 32-char UUID",
			uuid:        "10000000000000000000000000000001",
			expectError: false,
		},
		{
			name:        "uppercase UUID",
			uuid:        "A1B2C3D4-E5F6-7A8B-9C0D-1E2F3A4B5C6D",
			expectError: false,
		},
		{
			name:        "invalid UUID too short",
			uuid:        "10000000-0000-0000",
			expectError: true,
		},
		{
			name:        "invalid non-hex characters",
			uuid:        "zzzzzzzz-0000-0000-0000-000000000001",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DeriveCanonicalBatchID(tc.uuid)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error for %s, got nil (batch_id=%s)", tc.name, got)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for %s: %v", tc.name, err)
				}
				if !strings.HasPrefix(got, "0x") || len(got) != 66 {
					t.Errorf("expected 66 char canonical batch ID, got %s", got)
				}
			}
		})
	}
}

func TestSecondPreimageDefense(t *testing.T) {
	// TD-LEAF-V1 prefix: 0x00
	// Internal node prefix: 0x01
	// Verify that a leaf hash cannot collide with an internal node hash even with identical following bytes
	docHash := fmt.Sprintf("%x", sha256.Sum256([]byte("same-bytes")))
	leafHash, _, err := DeriveLeafHash("TD-CERT-0000000000000001", docHash)
	if err != nil {
		t.Fatalf("DeriveLeafHash failed: %v", err)
	}

	rawDoc, _ := ParseDocumentHash(docHash)
	internalHash := HashInternal(rawDoc, rawDoc)

	if leafHash == internalHash {
		t.Error("leaf hash collided with internal node hash; domain separation failed")
	}
}

func TestMaxProofDepth(t *testing.T) {
	var root [32]byte
	var leaf [32]byte
	root[0] = 0x01
	leaf[0] = 0x02

	// Proof with 20 nodes (boundary valid)
	proof20 := make([][32]byte, 20)
	for i := range proof20 {
		proof20[i][0] = byte(i + 1)
	}
	_, err := VerifyProof(root, leaf, proof20)
	if err != nil {
		t.Errorf("proof with 20 nodes should not error on depth check, got: %v", err)
	}

	// Proof with 21 nodes (boundary exceeds max)
	proof21 := make([][32]byte, 21)
	for i := range proof21 {
		proof21[i][0] = byte(i + 1)
	}
	valid, err := VerifyProof(root, leaf, proof21)
	if err == nil {
		t.Error("expected error for proof depth exceeding MaxProofDepth, got nil")
	}
	if valid {
		t.Error("expected valid=false for excessive proof depth")
	}
}

func TestOddNodePromotionTrees(t *testing.T) {
	// Test odd counts: 3, 5, 7, 9 leaves
	for _, count := range []int{3, 5, 7, 9} {
		t.Run(fmt.Sprintf("%d_leaves", count), func(t *testing.T) {
			inputs := make([]CertificateLeafInput, count)
			for i := 0; i < count; i++ {
				docHash := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("odd-doc-%d-%d", count, i))))
				inputs[i] = CertificateLeafInput{
					PublicID:     fmt.Sprintf("TD-CERT-%016d", i+1),
					DocumentHash: docHash,
				}
			}

			tree, err := BuildTree(inputs)
			if err != nil {
				t.Fatalf("BuildTree failed on %d leaves: %v", count, err)
			}

			if len(tree.Leaves) != count {
				t.Fatalf("expected %d leaves, got %d", count, len(tree.Leaves))
			}

			// Verify all leaf proofs
			for i, leaf := range tree.Leaves {
				valid, err := VerifyProof(tree.Root, leaf.LeafHash, leaf.Proof)
				if err != nil {
					t.Errorf("leaf %d VerifyProof error: %v", i, err)
				}
				if !valid {
					t.Errorf("leaf %d VerifyProof returned false", i)
				}
			}
		})
	}
}

func TestParseHex32(t *testing.T) {
	validHex := strings.Repeat("ab", 32)
	out, err := ParseHex32(validHex)
	if err != nil {
		t.Fatalf("unexpected error parsing valid hex: %v", err)
	}
	if hex.EncodeToString(out[:]) != validHex {
		t.Errorf("parsed hex mismatch: got %s, expected %s", hex.EncodeToString(out[:]), validHex)
	}

	// Test 0x prefix
	outPrefix, err := ParseHex32("0x" + validHex)
	if err != nil {
		t.Fatalf("unexpected error parsing 0x-prefixed hex: %v", err)
	}
	if outPrefix != out {
		t.Error("0x prefix produced different result")
	}

	// Test invalid length
	_, err = ParseHex32("abc")
	if err == nil {
		t.Error("expected error for short hex string")
	}

	// Test non-hex characters
	_, err = ParseHex32(strings.Repeat("zz", 32))
	if err == nil {
		t.Error("expected error for non-hex characters")
	}
}
