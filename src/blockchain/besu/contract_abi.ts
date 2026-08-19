import { parseAbi } from 'viem';

export const WOLVERINE_TRUST_REGISTRY_ABI = parseAbi([
  'function commitState(string tenantId, string databaseId, bytes16 checkpointId, uint64 commitSeq, uint32 epoch, bytes32 checkpointDigest, bytes32 stateMerkleRoot, bytes32 changeChainHead, bytes32 previousCommitmentDigest, bytes32 commitmentDigest, uint64 logicalTimestampUs, uint16 protocolVersion, bytes agentSignature, bytes customerSignature) external returns (bool)',
  'function getCommitment(bytes32 commitmentDigest) external view returns ((string tenantId, string databaseId, bytes16 checkpointId, uint64 commitSeq, uint32 epoch, bytes32 checkpointDigest, bytes32 stateMerkleRoot, bytes32 changeChainHead, bytes32 previousCommitmentDigest, bytes32 commitmentDigest, uint64 logicalTimestampUs, uint16 protocolVersion, bytes agentSignature, bytes customerSignature, uint256 blockNumber, uint256 blockTimestamp))',
  'function getLatestCommitment(string tenantId, string databaseId) external view returns ((string tenantId, string databaseId, bytes16 checkpointId, uint64 commitSeq, uint32 epoch, bytes32 checkpointDigest, bytes32 stateMerkleRoot, bytes32 changeChainHead, bytes32 previousCommitmentDigest, bytes32 commitmentDigest, uint64 logicalTimestampUs, uint16 protocolVersion, bytes agentSignature, bytes customerSignature, uint256 blockNumber, uint256 blockTimestamp))',
  'function getCommitmentBySequence(string tenantId, string databaseId, uint64 commitSeq) external view returns ((string tenantId, string databaseId, bytes16 checkpointId, uint64 commitSeq, uint32 epoch, bytes32 checkpointDigest, bytes32 stateMerkleRoot, bytes32 changeChainHead, bytes32 previousCommitmentDigest, bytes32 commitmentDigest, uint64 logicalTimestampUs, uint16 protocolVersion, bytes agentSignature, bytes customerSignature, uint256 blockNumber, uint256 blockTimestamp))',
  'function recordOptionalAnchor(bytes32 batchDigest, uint64 startSeq, uint64 endSeq, string publicChainId, bytes32 publicTxHash) external',
  'function advanceEpoch(uint32 newEpoch) external',
  'function currentEpoch() external view returns (uint32)',
  'function owner() external view returns (address)',
  'event CommitmentRecorded(string indexed tenantId, string indexed databaseId, uint64 indexed commitSeq, bytes32 commitmentDigest, bytes32 stateMerkleRoot, bytes32 changeChainHead, uint256 blockNumber)',
  'event EpochChanged(uint32 indexed oldEpoch, uint32 indexed newEpoch)',
  'event OptionalAnchorRecorded(bytes32 indexed batchDigest, uint64 startSeq, uint64 endSeq, string publicChainId, bytes32 publicTxHash)',
]);
