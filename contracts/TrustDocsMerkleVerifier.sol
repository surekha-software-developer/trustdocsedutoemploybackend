// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title TrustDocsMerkleVerifier
 * @notice Cryptographic verification library implementing TD-MERKLE-KECCAK256-V1,
 *         TD-LEAF-V1 leaf preimage derivation, and TD-PROOF-SORTED-V1 inclusion proofs.
 * @dev Leaf specification:
 *      keccak256(0x00 || uint16_be(public_id byte length) || ASCII(public_id) || raw 32-byte document_hash)
 *      Internal node specification:
 *      keccak256(0x01 || min(left, right) || max(left, right))
 *      Odd nodes are promoted directly during tree construction without being duplicated.
 *      Proofs are ordered bottom-to-top with maximum allowed depth of 20.
 */
library TrustDocsMerkleVerifier {
    uint256 public constant MAX_PROOF_DEPTH = 20;
    uint8 public constant LEAF_DOMAIN_SEPARATOR = 0x00;
    uint8 public constant INTERNAL_DOMAIN_SEPARATOR = 0x01;

    error ProofDepthExceeded(uint256 depth, uint256 maxDepth);
    error InvalidPublicIdLength(uint256 length);

    /**
     * @notice Computes the TD-LEAF-V1 leaf hash from a public certificate ID and 32-byte document hash.
     * @param publicId Human-readable certificate public ID (e.g. "TD-CERT-0000000000000001").
     * @param documentHash Raw 32-byte SHA-256 hash of the canonical certificate document.
     * @return leaf The derived 32-byte leaf hash.
     */
    function computeLeaf(string memory publicId, bytes32 documentHash) internal pure returns (bytes32) {
        bytes memory pidBytes = bytes(publicId);
        uint256 len = pidBytes.length;
        if (len == 0 || len > 65535) {
            revert InvalidPublicIdLength(len);
        }

        // Invariant: len is strictly validated to [1, 65535] (type(uint16).max), guaranteed not to truncate.
        return keccak256(
            abi.encodePacked(
                LEAF_DOMAIN_SEPARATOR,
                uint16(len),
                pidBytes,
                documentHash
            )
        );
    }

    /**
     * @notice Computes an internal node hash with sorted children and 0x01 domain prefix:
     *         keccak256(0x01 || min(left, right) || max(left, right))
     * @param a First node hash.
     * @param b Second node hash.
     * @return parent The 32-byte parent node hash.
     */
    function hashInternal(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        bytes32 left;
        bytes32 right;
        if (a <= b) {
            left = a;
            right = b;
        } else {
            left = b;
            right = a;
        }
        return keccak256(abi.encodePacked(INTERNAL_DOMAIN_SEPARATOR, left, right));
    }

    /**
     * @notice Evaluates a bottom-to-top Merkle proof against a root and leaf hash.
     * @param proof Array of sibling hashes ordered bottom-to-top.
     * @param root The claimed Merkle root.
     * @param leaf The leaf hash to verify.
     * @return isValid True if proof evaluates to root, false otherwise.
     */
    function verify(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool isValid) {
        if (proof.length > MAX_PROOF_DEPTH) {
            revert ProofDepthExceeded(proof.length, MAX_PROOF_DEPTH);
        }

        bytes32 current = leaf;
        // Invariant: proof length is strictly bounded by MAX_PROOF_DEPTH (20), preventing unbounded loops.
        for (uint256 i = 0; i < proof.length; i++) {
            current = hashInternal(current, proof[i]);
        }
        return current == root;
    }
}
