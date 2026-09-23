package merkle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type VectorFile struct {
	TreeAlgorithm       string           `json:"tree_algorithm"`
	TreeVersion         int              `json:"tree_version"`
	LeafEncodingVersion string           `json:"leaf_encoding_version"`
	ProofFormatVersion  string           `json:"proof_format_version"`
	GeneratedAt         string           `json:"generated_at"`
	BatchIDVectors      []BatchIDVector  `json:"batch_id_vectors"`
	TestCases           []TestCaseVector `json:"test_cases"`
}

type BatchIDVector struct {
	UUID             string `json:"uuid"`
	CanonicalBatchID string `json:"canonical_batch_id"`
}

type TestCaseVector struct {
	CaseName   string       `json:"case_name"`
	LeafCount  int          `json:"leaf_count"`
	MerkleRoot string       `json:"merkle_root"`
	Leaves     []LeafVector `json:"leaves"`
}

type LeafVector struct {
	PublicID     string   `json:"public_id"`
	DocumentHash string   `json:"document_hash"`
	LeafHash     string   `json:"leaf_hash"`
	LeafIndex    int      `json:"leaf_index"`
	Proof        []string `json:"proof"`
}

func loadTestVectors(t *testing.T) *VectorFile {
	t.Helper()

	// Try relative testdata directory first, then fallback
	paths := []string{
		filepath.Join("testdata", "merkle_vectors.json"),
		filepath.Join("..", "..", "..", "contracts", "testdata", "merkle_vectors.json"),
	}

	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("failed to locate merkle_vectors.json: %v", err)
	}

	var vf VectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("failed to unmarshal merkle_vectors.json: %v", err)
	}
	return &vf
}

func TestCanonicalBatchIDVectors(t *testing.T) {
	vf := loadTestVectors(t)

	if len(vf.BatchIDVectors) == 0 {
		t.Fatal("no canonical batch ID test vectors found in JSON")
	}

	for _, v := range vf.BatchIDVectors {
		t.Run("UUID_"+v.UUID, func(t *testing.T) {
			got, err := DeriveCanonicalBatchID(v.UUID)
			if err != nil {
				t.Fatalf("DeriveCanonicalBatchID(%q) error: %v", v.UUID, err)
			}
			if got != v.CanonicalBatchID {
				t.Errorf("DeriveCanonicalBatchID(%q) = %s, expected %s", v.UUID, got, v.CanonicalBatchID)
			}
			if !strings.HasPrefix(got, "0x") || len(got) != 66 {
				t.Errorf("DeriveCanonicalBatchID(%q) produced invalid format: %s", v.UUID, got)
			}
		})
	}
}

func TestVectorRecomputationAndVerification(t *testing.T) {
	vf := loadTestVectors(t)

	if vf.TreeAlgorithm != AlgorithmTDKeccak256V1 {
		t.Errorf("vector algorithm mismatch: expected %s, got %s", AlgorithmTDKeccak256V1, vf.TreeAlgorithm)
	}
	if vf.TreeVersion != TreeVersion1 {
		t.Errorf("vector tree version mismatch: expected %d, got %d", TreeVersion1, vf.TreeVersion)
	}
	if vf.LeafEncodingVersion != LeafEncodingTDLeafV1 {
		t.Errorf("vector leaf encoding mismatch: expected %s, got %s", LeafEncodingTDLeafV1, vf.LeafEncodingVersion)
	}
	if vf.ProofFormatVersion != ProofFormatTDSortedV1 {
		t.Errorf("vector proof format mismatch: expected %s, got %s", ProofFormatTDSortedV1, vf.ProofFormatVersion)
	}

	expectedCounts := map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true, 16: true, 100: true}
	seenCounts := make(map[int]bool)

	for _, tc := range vf.TestCases {
		seenCounts[tc.LeafCount] = true
		t.Run(tc.CaseName, func(t *testing.T) {
			if len(tc.Leaves) != tc.LeafCount {
				t.Fatalf("test case %s leaf count mismatch: declared %d, found %d",
					tc.CaseName, tc.LeafCount, len(tc.Leaves))
			}

			// Reconstruct inputs from the vector leaves
			inputs := make([]CertificateLeafInput, len(tc.Leaves))
			for i, l := range tc.Leaves {
				inputs[i] = CertificateLeafInput{
					PublicID:     l.PublicID,
					DocumentHash: l.DocumentHash,
				}
			}

			// Recompute tree with Go engine
			tree, err := BuildTree(inputs)
			if err != nil {
				t.Fatalf("BuildTree failed on %s: %v", tc.CaseName, err)
			}

			// Assert root match
			if tree.RootHex != tc.MerkleRoot {
				t.Errorf("root mismatch for %s: computed %s, vector expected %s",
					tc.CaseName, tree.RootHex, tc.MerkleRoot)
			}

			// Assert leaf count
			if len(tree.Leaves) != tc.LeafCount {
				t.Fatalf("computed leaf count mismatch: got %d, expected %d",
					len(tree.Leaves), tc.LeafCount)
			}

			// Assert each leaf, index, and proof
			for i, computed := range tree.Leaves {
				expected := tc.Leaves[i]

				if computed.LeafHashHex != expected.LeafHash {
					t.Errorf("leaf %d hash mismatch in %s: got %s, expected %s",
						i, tc.CaseName, computed.LeafHashHex, expected.LeafHash)
				}
				if computed.LeafIndex != expected.LeafIndex {
					t.Errorf("leaf %d index mismatch in %s: got %d, expected %d",
						i, tc.CaseName, computed.LeafIndex, expected.LeafIndex)
				}
				if len(computed.ProofHex) != len(expected.Proof) {
					t.Fatalf("leaf %d proof length mismatch in %s: got %d, expected %d",
						i, tc.CaseName, len(computed.ProofHex), len(expected.Proof))
				}
				for pIdx := range computed.ProofHex {
					if computed.ProofHex[pIdx] != expected.Proof[pIdx] {
						t.Errorf("leaf %d proof node %d mismatch in %s: got %s, expected %s",
							i, pIdx, tc.CaseName, computed.ProofHex[pIdx], expected.Proof[pIdx])
					}
				}

				// Independent mathematical verification of proof
				valid, err := VerifyProof(tree.Root, computed.LeafHash, computed.Proof)
				if err != nil {
					t.Errorf("VerifyProof error on leaf %d of %s: %v", i, tc.CaseName, err)
				}
				if !valid {
					t.Errorf("VerifyProof failed on leaf %d of %s", i, tc.CaseName)
				}

				// Hex string verification path
				validHex, err := VerifyProofHex(tree.RootHex, computed.LeafHashHex, computed.ProofHex)
				if err != nil {
					t.Errorf("VerifyProofHex error on leaf %d of %s: %v", i, tc.CaseName, err)
				}
				if !validHex {
					t.Errorf("VerifyProofHex failed on leaf %d of %s", i, tc.CaseName)
				}
			}
		})
	}

	for count := range expectedCounts {
		if !seenCounts[count] {
			t.Errorf("expected vector case with %d leaves not present in test data", count)
		}
	}
}

func TestVectorProofCorruption(t *testing.T) {
	vf := loadTestVectors(t)

	// Pick a multi-leaf case with proofs (e.g. 16 leaves)
	var targetCase *TestCaseVector
	for i := range vf.TestCases {
		if vf.TestCases[i].LeafCount == 16 {
			targetCase = &vf.TestCases[i]
			break
		}
	}
	if targetCase == nil {
		t.Fatal("16-leaf case not found for corruption test")
	}

	leaf := targetCase.Leaves[0]
	if len(leaf.Proof) == 0 {
		t.Fatal("target leaf has empty proof")
	}

	// 1. Corrupt root
	corruptedRoot := "0x" + strings.Repeat("0", 64)
	valid, err := VerifyProofHex(corruptedRoot, leaf.LeafHash, leaf.Proof)
	if err != nil {
		t.Fatalf("unexpected error on corrupted root: %v", err)
	}
	if valid {
		t.Error("VerifyProofHex succeeded with corrupted root")
	}

	// 2. Corrupt leaf hash
	corruptedLeaf := "0x" + strings.Repeat("f", 64)
	valid, err = VerifyProofHex(targetCase.MerkleRoot, corruptedLeaf, leaf.Proof)
	if err != nil {
		t.Fatalf("unexpected error on corrupted leaf: %v", err)
	}
	if valid {
		t.Error("VerifyProofHex succeeded with corrupted leaf hash")
	}

	// 3. Corrupt one proof node
	corruptedProof := make([]string, len(leaf.Proof))
	copy(corruptedProof, leaf.Proof)
	// Mutate last character of first proof node
	lastChar := corruptedProof[0][len(corruptedProof[0])-1]
	if lastChar == '0' {
		corruptedProof[0] = corruptedProof[0][:len(corruptedProof[0])-1] + "1"
	} else {
		corruptedProof[0] = corruptedProof[0][:len(corruptedProof[0])-1] + "0"
	}

	valid, err = VerifyProofHex(targetCase.MerkleRoot, leaf.LeafHash, corruptedProof)
	if err != nil {
		t.Fatalf("unexpected error on corrupted proof: %v", err)
	}
	if valid {
		t.Error("VerifyProofHex succeeded with corrupted sibling proof node")
	}

	// 4. Truncate proof (missing a sibling)
	truncatedProof := leaf.Proof[:len(leaf.Proof)-1]
	valid, err = VerifyProofHex(targetCase.MerkleRoot, leaf.LeafHash, truncatedProof)
	if err != nil {
		t.Fatalf("unexpected error on truncated proof: %v", err)
	}
	if valid {
		t.Error("VerifyProofHex succeeded with truncated proof")
	}
}
