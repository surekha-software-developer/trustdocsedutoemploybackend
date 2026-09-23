// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {TrustDocsAnchor} from "../TrustDocsAnchor.sol";
import {TrustDocsMerkleVerifier} from "../TrustDocsMerkleVerifier.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @dev Minimal external test harness allowing direct external CALL verification
 *      of internal library functions for cheatcodes like vm.expectRevert.
 */
contract MerkleVerifierHarness {
    function verify(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) external pure returns (bool) {
        return TrustDocsMerkleVerifier.verify(proof, root, leaf);
    }
}

contract TrustDocsAnchorTest is Test {
    TrustDocsAnchor internal anchor;
    MerkleVerifierHarness internal verifierHarness;

    event AnchorerUpdated(address indexed account, bool authorized);

    address internal owner = address(0x1001);
    address internal anchorer = address(0x1002);
    address internal unauthorized = address(0x1003);
    address internal newOwner = address(0x1004);

    string internal vectorJson;

    function setUp() public {
        vm.prank(owner);
        anchor = new TrustDocsAnchor(owner);

        verifierHarness = new MerkleVerifierHarness();

        // Explicitly authorize anchorer (separate authorization)
        vm.prank(owner);
        anchor.setAnchorer(anchorer, true);

        // Load canonical test vectors generated in Stage 1
        vectorJson = vm.readFile("contracts/testdata/merkle_vectors.json");
    }

    function _fromHexChar(uint8 c) internal pure returns (uint8) {
        if (c >= 48 && c <= 57) return c - 48; // '0'-'9'
        if (c >= 97 && c <= 102) return c - 87; // 'a'-'f'
        if (c >= 65 && c <= 70) return c - 55; // 'A'-'F'
        revert("invalid hex character");
    }

    function _parseUuidTo16Bytes(string memory uuidStr) internal pure returns (bytes memory) {
        bytes memory s = bytes(uuidStr);
        bytes memory out = new bytes(16);
        uint256 outIdx = 0;
        uint256 i = 0;
        while (i < s.length && outIdx < 16) {
            if (s[i] == "-") {
                i++;
                continue;
            }
            uint8 high = _fromHexChar(uint8(s[i]));
            uint8 low = _fromHexChar(uint8(s[i + 1]));
            out[outIdx] = bytes1((high << 4) | low);
            outIdx++;
            i += 2;
        }
        return out;
    }

    // ========================================================================
    // 1. CANONICAL BATCH ID EQUIVALENCE
    // ========================================================================
    function test_CanonicalBatchIdEquivalence() public view {
        for (uint256 i = 0; i < 5; i++) {
            string memory uuid = vm.parseJsonString(
                vectorJson,
                string.concat(".batch_id_vectors[", vm.toString(i), "].uuid")
            );
            bytes32 expected = vm.parseJsonBytes32(
                vectorJson,
                string.concat(".batch_id_vectors[", vm.toString(i), "].canonical_batch_id")
            );

            bytes memory rawUuid = _parseUuidTo16Bytes(uuid);
            bytes32 computed = keccak256(abi.encodePacked("trustdocs:batch:v1:", rawUuid));

            assertEq(computed, expected, "Canonical batch ID derivation mismatch between Go and Solidity");
        }
    }

    // ========================================================================
    // 2. VECTOR ROOTS AND PROOF VALIDATION HELPERS & INDEPENDENT TESTS
    // ========================================================================
    function _verifyVectorCase(uint256 caseIdx, uint256 expectedLeafCount) internal {
        bytes32 expectedRoot = vm.parseJsonBytes32(
            vectorJson,
            string.concat(".test_cases[", vm.toString(caseIdx), "].merkle_root")
        );
        uint256 count = vm.parseJsonUint(
            vectorJson,
            string.concat(".test_cases[", vm.toString(caseIdx), "].leaf_count")
        );
        assertEq(count, expectedLeafCount, "Leaf count mismatch for vector case");

        bytes32 batchId = keccak256(abi.encodePacked("canonical-batch-vector-", caseIdx));

        // Anchor the batch root on-chain as authorized anchorer
        vm.prank(anchorer);
        anchor.anchorRoot(expectedRoot, batchId, uint32(count));

        assertTrue(anchor.isRootAnchored(expectedRoot), "Root should be reported as anchored");
        TrustDocsAnchor.BatchRecord memory rec = anchor.getAnchor(expectedRoot);
        assertEq(rec.merkleRoot, expectedRoot, "Stored root mismatch");
        assertEq(rec.batchId, batchId, "Stored batchId mismatch");
        assertEq(rec.certificateCount, uint32(count), "Stored count mismatch");
        assertEq(rec.submitter, anchorer, "Stored submitter mismatch");

        // Verify every leaf, leaf hash, proof, and certificate in this case
        for (uint256 j = 0; j < count; j++) {
            string memory pid = vm.parseJsonString(
                vectorJson,
                string.concat(".test_cases[", vm.toString(caseIdx), "].leaves[", vm.toString(j), "].public_id")
            );
            bytes32 docHash = vm.parseJsonBytes32(
                vectorJson,
                string.concat(".test_cases[", vm.toString(caseIdx), "].leaves[", vm.toString(j), "].document_hash")
            );
            bytes32 expectedLeaf = vm.parseJsonBytes32(
                vectorJson,
                string.concat(".test_cases[", vm.toString(caseIdx), "].leaves[", vm.toString(j), "].leaf_hash")
            );
            bytes32[] memory proof = vm.parseJsonBytes32Array(
                vectorJson,
                string.concat(".test_cases[", vm.toString(caseIdx), "].leaves[", vm.toString(j), "].proof")
            );

            // 1. Verify leaf hash derivation equivalence
            bytes32 computedLeaf = TrustDocsMerkleVerifier.computeLeaf(pid, docHash);
            assertEq(computedLeaf, expectedLeaf, "Leaf hash computation mismatch with Go vector");

            // 2. Verify proof directly via library
            bool libValid = TrustDocsMerkleVerifier.verify(proof, expectedRoot, computedLeaf);
            assertTrue(libValid, "Direct library Merkle proof verification failed");

            // 3. Verify proof on-chain via anchor contract
            bool onChainValid = anchor.verifyProof(expectedRoot, computedLeaf, proof);
            assertTrue(onChainValid, "On-chain verifyProof failed");

            // 4. Verify full certificate on-chain
            bool certValid = anchor.verifyCertificate(expectedRoot, pid, docHash, proof);
            assertTrue(certValid, "On-chain verifyCertificate failed");
        }
    }

    function test_VectorRootAndProofs_1Leaf() public {
        _verifyVectorCase(0, 1);
    }

    function test_VectorRootAndProofs_2Leaves() public {
        _verifyVectorCase(1, 2);
    }

    function test_VectorRootAndProofs_3Leaves() public {
        _verifyVectorCase(2, 3);
    }

    function test_VectorRootAndProofs_4Leaves() public {
        _verifyVectorCase(3, 4);
    }

    function test_VectorRootAndProofs_5Leaves() public {
        _verifyVectorCase(4, 5);
    }

    function test_VectorRootAndProofs_16Leaves() public {
        _verifyVectorCase(5, 16);
    }

    function test_VectorRootAndProofs_100Leaves() public {
        _verifyVectorCase(6, 100);
    }

    // ========================================================================
    // 3. CORRUPTED ROOTS, LEAVES, AND PROOFS REJECTION
    // ========================================================================
    function test_CorruptedRootsLeavesAndProofsRejection() public {
        // Use the 16-leaf case (caseIdx = 5)
        bytes32 root = vm.parseJsonBytes32(vectorJson, ".test_cases[5].merkle_root");
        uint256 count = vm.parseJsonUint(vectorJson, ".test_cases[5].leaf_count");
        bytes32 batchId = keccak256("batch-16-corruption-test");

        vm.prank(anchorer);
        anchor.anchorRoot(root, batchId, uint32(count));

        string memory pid = vm.parseJsonString(vectorJson, ".test_cases[5].leaves[0].public_id");
        bytes32 docHash = vm.parseJsonBytes32(vectorJson, ".test_cases[5].leaves[0].document_hash");
        bytes32 leaf = vm.parseJsonBytes32(vectorJson, ".test_cases[5].leaves[0].leaf_hash");
        bytes32[] memory proof = vm.parseJsonBytes32Array(vectorJson, ".test_cases[5].leaves[0].proof");

        // 1. Corrupted leaf hash
        bytes32 badLeaf = bytes32(uint256(leaf) ^ 0xff);
        assertFalse(anchor.verifyProof(root, badLeaf, proof), "Corrupted leaf should return false");

        // 2. Corrupted document hash in certificate verification
        bytes32 badDocHash = bytes32(uint256(docHash) ^ 0xff);
        assertFalse(anchor.verifyCertificate(root, pid, badDocHash, proof), "Corrupted doc hash should return false");

        // 3. Corrupted public ID
        assertFalse(anchor.verifyCertificate(root, "TD-CERT-CORRUPTED000", docHash, proof), "Corrupted public ID should return false");

        // 4. Corrupted proof sibling node
        bytes32[] memory badProof = new bytes32[](proof.length);
        for (uint256 i = 0; i < proof.length; i++) {
            badProof[i] = proof[i];
        }
        badProof[0] = bytes32(uint256(badProof[0]) ^ 0x01);
        assertFalse(anchor.verifyProof(root, leaf, badProof), "Corrupted proof node should return false");

        // 5. Corrupted root (must revert because root is not anchored)
        bytes32 badRoot = bytes32(uint256(root) ^ 0x01);
        vm.expectRevert(abi.encodeWithSelector(TrustDocsAnchor.RootNotAnchored.selector, badRoot));
        anchor.verifyProof(badRoot, leaf, proof);
    }

    // ========================================================================
    // 4. DUPLICATE ROOT REJECTION
    // ========================================================================
    function test_DuplicateRootRejection() public {
        bytes32 root = bytes32(uint256(0xaaa1));
        bytes32 batchId1 = bytes32(uint256(0xb1));
        bytes32 batchId2 = bytes32(uint256(0xb2));

        vm.prank(anchorer);
        anchor.anchorRoot(root, batchId1, 10);

        vm.prank(anchorer);
        vm.expectRevert(abi.encodeWithSelector(TrustDocsAnchor.RootAlreadyAnchored.selector, root));
        anchor.anchorRoot(root, batchId2, 10);
    }

    // ========================================================================
    // 5. DUPLICATE BATCH ID REJECTION
    // ========================================================================
    function test_DuplicateBatchIdRejection() public {
        bytes32 root1 = bytes32(uint256(0xaaa1));
        bytes32 root2 = bytes32(uint256(0xaaa2));
        bytes32 batchId = bytes32(uint256(0xb1));

        vm.prank(anchorer);
        anchor.anchorRoot(root1, batchId, 10);

        vm.prank(anchorer);
        vm.expectRevert(abi.encodeWithSelector(TrustDocsAnchor.BatchIdAlreadyAnchored.selector, batchId));
        anchor.anchorRoot(root2, batchId, 10);
    }

    // ========================================================================
    // 6. ZERO ROOT AND ZERO BATCH ID REJECTION
    // ========================================================================
    function test_ZeroRootAndZeroBatchIdRejection() public {
        bytes32 validRoot = bytes32(uint256(0x1234));
        bytes32 validBatch = bytes32(uint256(0x5678));

        vm.startPrank(anchorer);

        vm.expectRevert(TrustDocsAnchor.InvalidZeroRoot.selector);
        anchor.anchorRoot(bytes32(0), validBatch, 1);

        vm.expectRevert(TrustDocsAnchor.InvalidZeroBatchId.selector);
        anchor.anchorRoot(validRoot, bytes32(0), 1);

        vm.expectRevert(TrustDocsAnchor.InvalidZeroCertificateCount.selector);
        anchor.anchorRoot(validRoot, validBatch, 0);

        vm.stopPrank();
    }

    // ========================================================================
    // 7. UNAUTHORIZED ANCHORING REJECTION
    // ========================================================================
    function test_UnauthorizedAnchoringRejection() public {
        bytes32 root = bytes32(uint256(0x1111));
        bytes32 batch = bytes32(uint256(0x2222));

        // 1. Random unauthorized address
        vm.prank(unauthorized);
        vm.expectRevert(abi.encodeWithSelector(TrustDocsAnchor.UnauthorizedAnchorer.selector, unauthorized));
        anchor.anchorRoot(root, batch, 1);

        // 2. Owner without explicit anchorer role
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(TrustDocsAnchor.UnauthorizedAnchorer.selector, owner));
        anchor.anchorRoot(root, batch, 1);
    }

    // ========================================================================
    // 8. OWNER AND ANCHORER PERMISSIONS
    // ========================================================================
    function test_OwnerAnchorerPermissions() public {
        // Non-owner cannot update anchorers
        vm.prank(unauthorized);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, unauthorized));
        anchor.setAnchorer(unauthorized, true);

        // Owner grants authorization (assert AnchorerUpdated event emitted)
        vm.expectEmit(true, false, false, true);
        emit AnchorerUpdated(unauthorized, true);
        vm.prank(owner);
        anchor.setAnchorer(unauthorized, true);
        assertTrue(anchor.isAnchorer(unauthorized), "Should now be authorized anchorer");

        // Owner revokes authorization (assert AnchorerUpdated event emitted)
        vm.expectEmit(true, false, false, true);
        emit AnchorerUpdated(unauthorized, false);
        vm.prank(owner);
        anchor.setAnchorer(unauthorized, false);
        assertFalse(anchor.isAnchorer(unauthorized), "Should no longer be authorized anchorer");

        // Cannot set zero address
        vm.prank(owner);
        vm.expectRevert(TrustDocsAnchor.InvalidZeroAddress.selector);
        anchor.setAnchorer(address(0), true);
    }

    // ========================================================================
    // 9. PAUSE AND UNPAUSE BEHAVIOR
    // ========================================================================
    function test_PauseUnpauseBehavior() public {
        bytes32 root = bytes32(uint256(0x1111));
        bytes32 batch = bytes32(uint256(0x2222));

        // Non-owner cannot pause
        vm.prank(unauthorized);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, unauthorized));
        anchor.pause();

        // Owner pauses
        vm.prank(owner);
        anchor.pause();
        assertTrue(anchor.paused(), "Contract should be paused");

        // Anchoring blocked while paused
        vm.prank(anchorer);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        anchor.anchorRoot(root, batch, 1);

        // Owner unpauses
        vm.prank(owner);
        anchor.unpause();
        assertFalse(anchor.paused(), "Contract should be unpaused");

        // Anchoring succeeds after unpause
        vm.prank(anchorer);
        anchor.anchorRoot(root, batch, 1);
        assertTrue(anchor.isRootAnchored(root), "Root should be anchored after unpause");
    }

    // ========================================================================
    // 10. OWNERSHIP TRANSFER VIA OWNABLE2STEP
    // ========================================================================
    function test_Ownable2StepTransfer() public {
        // Step 1: Initiate transfer
        vm.prank(owner);
        anchor.transferOwnership(newOwner);

        assertEq(anchor.owner(), owner, "Owner should not change until accepted");
        assertEq(anchor.pendingOwner(), newOwner, "Pending owner should be recorded");

        // Unauthorized account cannot accept
        vm.prank(unauthorized);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, unauthorized));
        anchor.acceptOwnership();

        // Step 2: Pending owner accepts
        vm.prank(newOwner);
        anchor.acceptOwnership();

        assertEq(anchor.owner(), newOwner, "Ownership transfer complete");
        assertEq(anchor.pendingOwner(), address(0), "Pending owner should be cleared");
    }

    // ========================================================================
    // 11. UNREGISTERED ROOT VERIFICATION REJECTION
    // ========================================================================
    function test_UnregisteredRootVerificationRejection() public {
        bytes32 unanchoredRoot = bytes32(uint256(0x999999));
        bytes32 leaf = bytes32(uint256(0x1));
        bytes32[] memory proof = new bytes32[](0);

        vm.expectRevert(abi.encodeWithSelector(TrustDocsAnchor.RootNotAnchored.selector, unanchoredRoot));
        anchor.verifyProof(unanchoredRoot, leaf, proof);

        vm.expectRevert(abi.encodeWithSelector(TrustDocsAnchor.RootNotAnchored.selector, unanchoredRoot));
        anchor.getAnchor(unanchoredRoot);
    }

    // ========================================================================
    // 12. PROOF DEPTH EXCEEDED REJECTION
    // ========================================================================
    function test_ProofDepthExceededRejection() public {
        bytes32 root = bytes32(uint256(0x100));
        bytes32 batch = bytes32(uint256(0x200));

        vm.prank(anchorer);
        anchor.anchorRoot(root, batch, 1);

        bytes32 leaf = bytes32(uint256(0x1));
        bytes32[] memory proof21 = new bytes32[](21);
        for (uint256 i = 0; i < 21; i++) {
            proof21[i] = bytes32(i + 1);
        }

        // 1. Direct external CALL to library test harness
        vm.expectRevert(abi.encodeWithSelector(TrustDocsMerkleVerifier.ProofDepthExceeded.selector, 21, 20));
        verifierHarness.verify(proof21, root, leaf);

        // 2. External CALL to TrustDocsAnchor.verifyProof
        vm.expectRevert(abi.encodeWithSelector(TrustDocsMerkleVerifier.ProofDepthExceeded.selector, 21, 20));
        anchor.verifyProof(root, leaf, proof21);

        // 3. External CALL to TrustDocsAnchor.verifyCertificate
        vm.expectRevert(abi.encodeWithSelector(TrustDocsMerkleVerifier.ProofDepthExceeded.selector, 21, 20));
        anchor.verifyCertificate(root, "TD-CERT-0000000000000001", bytes32(uint256(0x99)), proof21);
    }
}
