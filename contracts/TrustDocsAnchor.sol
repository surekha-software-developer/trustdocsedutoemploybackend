// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {TrustDocsMerkleVerifier} from "./TrustDocsMerkleVerifier.sol";

/**
 * @title TrustDocsAnchor
 * @notice Immutable blockchain registry for anchoring cryptographic Merkle roots of finalized
 *         academic certificate batches.
 * @dev Enforces strict root uniqueness, batch ID uniqueness, separate anchorer authorization,
 *      emergency pausing, and on-chain verification of inclusion proofs.
 *      No student PII, document hashes, or raw certificate data are ever stored on-chain.
 */
contract TrustDocsAnchor is Ownable2Step, Pausable {
    struct BatchRecord {
        bytes32 merkleRoot;
        bytes32 batchId;
        uint32 certificateCount;
        uint64 anchoredAt;
        address submitter;
    }

    /// @notice Maps canonical Merkle root to its anchored batch record.
    mapping(bytes32 => BatchRecord) public anchorsByRoot;

    /// @notice Maps canonical batch ID to its registered Merkle root.
    mapping(bytes32 => bytes32) public rootByBatchId;

    /// @notice Whitelist of authorized anchorer addresses (separate from owner).
    mapping(address => bool) public isAnchorer;

    // Events
    event RootAnchored(
        bytes32 indexed merkleRoot,
        bytes32 indexed batchId,
        address indexed submitter,
        uint32 certificateCount,
        uint64 anchoredAt
    );

    event AnchorerUpdated(address indexed account, bool authorized);

    // Custom Errors
    error UnauthorizedAnchorer(address caller);
    error RootAlreadyAnchored(bytes32 root);
    error BatchIdAlreadyAnchored(bytes32 batchId);
    error RootNotAnchored(bytes32 root);
    error InvalidZeroRoot();
    error InvalidZeroBatchId();
    error InvalidZeroCertificateCount();
    error InvalidZeroAddress();

    /**
     * @notice Restricts execution strictly to authorized anchorer accounts.
     * @dev The owner is intentionally NOT automatically an anchorer unless explicitly authorized.
     */
    modifier onlyAnchorer() {
        if (!isAnchorer[msg.sender]) {
            revert UnauthorizedAnchorer(msg.sender);
        }
        _;
    }

    /**
     * @notice Initializes contract with an initial owner using two-step transfer pattern.
     * @param initialOwner Address of the contract owner.
     */
    constructor(address initialOwner) Ownable(initialOwner) {
        if (initialOwner == address(0)) {
            revert InvalidZeroAddress();
        }
    }

    /**
     * @notice Anchors a finalized Merkle batch root to the blockchain.
     * @param root The 32-byte Keccak-256 Merkle root.
     * @param batchId The 32-byte canonical batch identifier.
     * @param certificateCount Total number of certificates included in this batch.
     */
    function anchorRoot(
        bytes32 root,
        bytes32 batchId,
        uint32 certificateCount
    ) external onlyAnchorer whenNotPaused {
        if (root == bytes32(0)) {
            revert InvalidZeroRoot();
        }
        if (batchId == bytes32(0)) {
            revert InvalidZeroBatchId();
        }
        if (certificateCount == 0) {
            revert InvalidZeroCertificateCount();
        }
        if (anchorsByRoot[root].anchoredAt != 0) {
            revert RootAlreadyAnchored(root);
        }
        if (rootByBatchId[batchId] != bytes32(0)) {
            revert BatchIdAlreadyAnchored(batchId);
        }

        // Invariant: block.timestamp fits safely in uint64 (valid through year 584,942,417,355).
        uint64 timestamp = uint64(block.timestamp);

        anchorsByRoot[root] = BatchRecord({
            merkleRoot: root,
            batchId: batchId,
            certificateCount: certificateCount,
            anchoredAt: timestamp,
            submitter: msg.sender
        });

        rootByBatchId[batchId] = root;

        emit RootAnchored(root, batchId, msg.sender, certificateCount, timestamp);
    }

    /**
     * @notice Verifies an inclusion proof directly against an anchored Merkle root.
     * @dev Must only validate proofs for roots already anchored in this contract.
     * @param root The claimed 32-byte Merkle root.
     * @param leaf The 32-byte certificate leaf hash.
     * @param proof Bottom-to-top sibling node hashes.
     * @return isValid True if proof is valid under the anchored root.
     */
    function verifyProof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] calldata proof
    ) external view returns (bool isValid) {
        if (anchorsByRoot[root].anchoredAt == 0) {
            revert RootNotAnchored(root);
        }
        return TrustDocsMerkleVerifier.verify(proof, root, leaf);
    }

    /**
     * @notice Derives the leaf hash from certificate attributes and verifies its on-chain inclusion.
     * @param root The claimed 32-byte Merkle root.
     * @param publicId Certificate public ID (e.g. "TD-CERT-0000000000000001").
     * @param documentHash Raw 32-byte SHA-256 hash of the canonical certificate document.
     * @param proof Bottom-to-top sibling node hashes.
     * @return isValid True if certificate leaf is verified under the anchored root.
     */
    function verifyCertificate(
        bytes32 root,
        string calldata publicId,
        bytes32 documentHash,
        bytes32[] calldata proof
    ) external view returns (bool isValid) {
        if (anchorsByRoot[root].anchoredAt == 0) {
            revert RootNotAnchored(root);
        }
        bytes32 leaf = TrustDocsMerkleVerifier.computeLeaf(publicId, documentHash);
        return TrustDocsMerkleVerifier.verify(proof, root, leaf);
    }

    /**
     * @notice Checks whether a given Merkle root has been anchored.
     * @param root The 32-byte Merkle root.
     * @return True if root is anchored, false otherwise.
     */
    function isRootAnchored(bytes32 root) external view returns (bool) {
        return anchorsByRoot[root].anchoredAt != 0;
    }

    /**
     * @notice Retrieves the anchored batch record for a Merkle root.
     * @param root The 32-byte Merkle root.
     * @return record The BatchRecord struct.
     */
    function getAnchor(bytes32 root) external view returns (BatchRecord memory record) {
        if (anchorsByRoot[root].anchoredAt == 0) {
            revert RootNotAnchored(root);
        }
        return anchorsByRoot[root];
    }

    /**
     * @notice Grants or revokes anchorer authorization for an address.
     * @param account Target address.
     * @param authorized True to authorize, false to revoke.
     */
    function setAnchorer(address account, bool authorized) external onlyOwner {
        if (account == address(0)) {
            revert InvalidZeroAddress();
        }
        isAnchorer[account] = authorized;
        emit AnchorerUpdated(account, authorized);
    }

    /**
     * @notice Pauses contract anchoring operations (owner emergency control).
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Unpauses contract anchoring operations.
     */
    function unpause() external onlyOwner {
        _unpause();
    }
}
