// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title WolverineTrustRegistry
 * @notice Canonical on-chain cryptographic state registry for WolverineDB.
 * Records state commitments, Merkle roots, and dual attestations with zero plaintext database data.
 */
contract WolverineTrustRegistry {
    struct StateCommitment {
        string tenantId;
        string databaseId;
        bytes16 checkpointId;
        uint64 commitSeq;
        uint32 epoch;
        bytes32 checkpointDigest;
        bytes32 stateMerkleRoot;
        bytes32 changeChainHead;
        bytes32 previousCommitmentDigest;
        bytes32 commitmentDigest;
        uint64 logicalTimestampUs;
        uint16 protocolVersion;
        bytes agentSignature;
        bytes customerSignature;
        uint256 blockNumber;
        uint256 blockTimestamp;
    }

    // Owner / Gateway Operator
    address public owner;
    uint32 public currentEpoch;

    // commitmentDigest => StateCommitment
    mapping(bytes32 => StateCommitment) private commitments;

    // tenantId => databaseId => latest commitSeq
    mapping(string => mapping(string => uint64)) private latestSequence;

    // tenantId => databaseId => commitSeq => commitmentDigest
    mapping(string => mapping(string => mapping(uint64 => bytes32))) private sequenceIndex;

    // Events
    event CommitmentRecorded(
        string indexed tenantId,
        string indexed databaseId,
        uint64 indexed commitSeq,
        bytes32 commitmentDigest,
        bytes32 stateMerkleRoot,
        bytes32 changeChainHead,
        uint256 blockNumber
    );

    event EpochChanged(uint32 indexed oldEpoch, uint32 indexed newEpoch);

    event OptionalAnchorRecorded(
        bytes32 indexed batchDigest,
        uint64 startSeq,
        uint64 endSeq,
        string publicChainId,
        bytes32 publicTxHash
    );

    error SequenceGapDetected(uint64 expected, uint64 received);
    error DuplicateCommitment(bytes32 commitmentDigest);
    error InvalidPreviousCommitment(bytes32 expected, bytes32 received);
    error Unauthorized();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor() {
        owner = msg.sender;
        currentEpoch = 1;
    }

    /**
     * @notice Records a dual-signed database state commitment on the authoritative Besu ledger.
     */
    function commitState(
        string calldata tenantId,
        string calldata databaseId,
        bytes16 checkpointId,
        uint64 commitSeq,
        uint32 epoch,
        bytes32 checkpointDigest,
        bytes32 stateMerkleRoot,
        bytes32 changeChainHead,
        bytes32 previousCommitmentDigest,
        bytes32 commitmentDigest,
        uint64 logicalTimestampUs,
        uint16 protocolVersion,
        bytes calldata agentSignature,
        bytes calldata customerSignature
    ) external returns (bool) {
        if (commitments[commitmentDigest].blockNumber != 0) {
            revert DuplicateCommitment(commitmentDigest);
        }

        uint64 currentHead = latestSequence[tenantId][databaseId];

        // Sequence monotonicity enforcement
        if (currentHead == 0) {
            // First commitment for this tenant/database
            if (commitSeq != 1) {
                revert SequenceGapDetected(1, commitSeq);
            }
        } else {
            if (commitSeq != currentHead + 1) {
                revert SequenceGapDetected(currentHead + 1, commitSeq);
            }
            // Verify previous commitment linkage
            bytes32 expectedPrev = sequenceIndex[tenantId][databaseId][currentHead];
            if (expectedPrev != previousCommitmentDigest) {
                revert InvalidPreviousCommitment(expectedPrev, previousCommitmentDigest);
            }
        }

        StateCommitment memory entry = StateCommitment({
            tenantId: tenantId,
            databaseId: databaseId,
            checkpointId: checkpointId,
            commitSeq: commitSeq,
            epoch: epoch,
            checkpointDigest: checkpointDigest,
            stateMerkleRoot: stateMerkleRoot,
            changeChainHead: changeChainHead,
            previousCommitmentDigest: previousCommitmentDigest,
            commitmentDigest: commitmentDigest,
            logicalTimestampUs: logicalTimestampUs,
            protocolVersion: protocolVersion,
            agentSignature: agentSignature,
            customerSignature: customerSignature,
            blockNumber: block.number,
            blockTimestamp: block.timestamp
        });

        commitments[commitmentDigest] = entry;
        latestSequence[tenantId][databaseId] = commitSeq;
        sequenceIndex[tenantId][databaseId][commitSeq] = commitmentDigest;

        emit CommitmentRecorded(
            tenantId,
            databaseId,
            commitSeq,
            commitmentDigest,
            stateMerkleRoot,
            changeChainHead,
            block.number
        );

        return true;
    }

    /**
     * @notice Retrieves full commitment record by its unique commitmentDigest.
     */
    function getCommitment(bytes32 commitmentDigest)
        external
        view
        returns (StateCommitment memory)
    {
        return commitments[commitmentDigest];
    }

    /**
     * @notice Retrieves the latest commitment record for a tenant and database.
     */
    function getLatestCommitment(string calldata tenantId, string calldata databaseId)
        external
        view
        returns (StateCommitment memory)
    {
        uint64 head = latestSequence[tenantId][databaseId];
        if (head == 0) {
            return commitments[bytes32(0)];
        }
        bytes32 digest = sequenceIndex[tenantId][databaseId][head];
        return commitments[digest];
    }

    /**
     * @notice Retrieves commitment by sequence number.
     */
    function getCommitmentBySequence(
        string calldata tenantId,
        string calldata databaseId,
        uint64 commitSeq
    ) external view returns (StateCommitment memory) {
        bytes32 digest = sequenceIndex[tenantId][databaseId][commitSeq];
        return commitments[digest];
    }

    /**
     * @notice Records an optional public-chain anchor reference.
     */
    function recordOptionalAnchor(
        bytes32 batchDigest,
        uint64 startSeq,
        uint64 endSeq,
        string calldata publicChainId,
        bytes32 publicTxHash
    ) external onlyOwner {
        emit OptionalAnchorRecorded(batchDigest, startSeq, endSeq, publicChainId, publicTxHash);
    }

    /**
     * @notice Advances current epoch.
     */
    function advanceEpoch(uint32 newEpoch) external onlyOwner {
        uint32 old = currentEpoch;
        currentEpoch = newEpoch;
        emit EpochChanged(old, newEpoch);
    }
}
