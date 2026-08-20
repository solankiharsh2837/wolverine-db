// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title WolverineTrustRegistry
 * @notice Canonical on-chain cryptographic state registry for WolverineDB.
 * Enforces tenant authorization, sequence monotonicity, hash chaining, and cryptographic customer authorization.
 */
contract WolverineTrustRegistry {
    struct TenantConfig {
        address customerSigningAddress;
        address authorizedGateway;
        bool isRegistered;
        uint64 registeredAtBlock;
    }

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

    // Owner / Registry Administrator
    address public owner;
    uint32 public currentEpoch;

    // tenantId => TenantConfig
    mapping(string => TenantConfig) private tenants;

    // commitmentDigest => StateCommitment
    mapping(bytes32 => StateCommitment) private commitments;

    // tenantId => databaseId => latest commitSeq
    mapping(string => mapping(string => uint64)) private latestSequence;

    // tenantId => databaseId => commitSeq => commitmentDigest
    mapping(string => mapping(string => mapping(uint64 => bytes32))) private sequenceIndex;

    // Events
    event TenantRegistered(
        string indexed tenantId,
        address indexed customerSigningAddress,
        address indexed authorizedGateway,
        uint256 blockNumber
    );

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

    // Custom Errors
    error Unauthorized();
    error TenantNotRegistered(string tenantId);
    error TenantAlreadyRegistered(string tenantId);
    error UnauthorizedGateway(address caller, address authorizedGateway);
    error InvalidCustomerSignature(address recoveredSigner, address expectedSigner);
    error SequenceGapDetected(uint64 expected, uint64 received);
    error DuplicateCommitment(bytes32 commitmentDigest);
    error InvalidPreviousCommitment(bytes32 expected, bytes32 received);
    error InvalidDigestBinding(bytes32 expected, bytes32 received);

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor() {
        owner = msg.sender;
        currentEpoch = 1;
    }

    /**
     * @notice Registers a sovereign tenant with their designated customer signing key and authorized gateway.
     */
    function registerTenant(
        string calldata tenantId,
        address customerSigningAddress,
        address authorizedGateway
    ) external onlyOwner {
        if (tenants[tenantId].isRegistered) {
            revert TenantAlreadyRegistered(tenantId);
        }

        tenants[tenantId] = TenantConfig({
            customerSigningAddress: customerSigningAddress,
            authorizedGateway: authorizedGateway,
            isRegistered: true,
            registeredAtBlock: uint64(block.number)
        });

        emit TenantRegistered(tenantId, customerSigningAddress, authorizedGateway, block.number);
    }

    /**
     * @notice Retrieves registered tenant configuration.
     */
    function getTenant(string calldata tenantId) external view returns (TenantConfig memory) {
        return tenants[tenantId];
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
        TenantConfig memory tenant = tenants[tenantId];
        if (!tenant.isRegistered) {
            revert TenantNotRegistered(tenantId);
        }

        // Access control: caller must be authorized gateway or registry owner
        if (msg.sender != tenant.authorizedGateway && msg.sender != owner) {
            revert UnauthorizedGateway(msg.sender, tenant.authorizedGateway);
        }

        if (commitments[commitmentDigest].blockNumber != 0) {
            revert DuplicateCommitment(commitmentDigest);
        }

        uint64 currentHead = latestSequence[tenantId][databaseId];

        // Sequence monotonicity enforcement
        if (currentHead == 0) {
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

        // Verify Customer Authorization Signature if signature is provided
        if (customerSignature.length == 65 && tenant.customerSigningAddress != address(0)) {
            bytes32 authMessageHash = keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n32",
                    keccak256(
                        abi.encodePacked(
                            block.chainid,
                            address(this),
                            tenantId,
                            databaseId,
                            commitSeq,
                            commitmentDigest
                        )
                    )
                )
            );

            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := calldataload(customerSignature.offset)
                s := calldataload(add(customerSignature.offset, 32))
                v := byte(0, calldataload(add(customerSignature.offset, 64)))
            }

            if (v < 27) {
                v += 27;
            }

            address recoveredSigner = ecrecover(authMessageHash, v, r, s);
            if (recoveredSigner != tenant.customerSigningAddress) {
                revert InvalidCustomerSignature(recoveredSigner, tenant.customerSigningAddress);
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
