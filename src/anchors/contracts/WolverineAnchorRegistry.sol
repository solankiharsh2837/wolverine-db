// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title WolverineAnchorRegistry
 * @notice Pure temporal notary registry for WolverineDB batch Merkle roots.
 * @dev Deliberately stupid by design: Does not parse SQL, does not inspect database semantics,
 * and does not execute database consensus. It simply notarizes that at block timestamp T,
 * Wolverine committed to batch Merkle root R.
 */
contract WolverineAnchorRegistry {
    struct AnchorRecord {
        uint64 epoch;
        uint64 startSeq;
        uint64 endSeq;
        bytes32 batchRoot;
        bytes32 previousBatchRoot;
        uint256 blockNumber;
        uint256 blockTimestamp;
    }

    // Mapping from endSeq => AnchorRecord
    mapping(uint64 => AnchorRecord) public anchors;
    uint64 public latestAnchoredSeq;
    bytes32 public latestBatchRoot;

    event StateAnchored(
        uint64 indexed endSeq,
        uint64 indexed epoch,
        uint64 startSeq,
        bytes32 batchRoot,
        bytes32 previousBatchRoot,
        uint256 blockNumber,
        uint256 blockTimestamp
    );

    error SequenceNotMonotonic(uint64 startSeq, uint64 expectedStartSeq);
    error InvalidSequenceRange(uint64 startSeq, uint64 endSeq);
    error PreviousBatchRootMismatch(bytes32 previousBatchRoot, bytes32 expectedPreviousRoot);

    /**
     * @notice Notarizes an anchor batch on-chain.
     */
    function anchorBatch(
        uint64 epoch,
        uint64 startSeq,
        uint64 endSeq,
        bytes32 batchRoot,
        bytes32 previousBatchRoot
    ) external {
        if (endSeq < startSeq) {
            revert InvalidSequenceRange(startSeq, endSeq);
        }

        if (latestAnchoredSeq > 0) {
            if (startSeq != latestAnchoredSeq + 1) {
                revert SequenceNotMonotonic(startSeq, latestAnchoredSeq + 1);
            }
            if (previousBatchRoot != latestBatchRoot) {
                revert PreviousBatchRootMismatch(previousBatchRoot, latestBatchRoot);
            }
        }

        AnchorRecord memory record = AnchorRecord({
            epoch: epoch,
            startSeq: startSeq,
            endSeq: endSeq,
            batchRoot: batchRoot,
            previousBatchRoot: previousBatchRoot,
            blockNumber: block.number,
            blockTimestamp: block.timestamp
        });

        anchors[endSeq] = record;
        latestAnchoredSeq = endSeq;
        latestBatchRoot = batchRoot;

        emit StateAnchored(
            endSeq,
            epoch,
            startSeq,
            batchRoot,
            previousBatchRoot,
            block.number,
            block.timestamp
        );
    }
}
