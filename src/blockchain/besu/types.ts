export interface BesuNodeConfig {
  rpcUrl: string;
  wsUrl?: string;
  chainId: number;
  contractAddress: `0x${string}`;
  operatorPrivateKeyHex?: `0x${string}`;
  timeoutMs?: number;
}

export interface BesuStateCommitmentInput {
  tenantId: string;
  databaseId: string;
  checkpointIdHex: string; // 16 bytes hex (32 chars)
  commitSeq: bigint;
  epoch: number;
  checkpointDigestHex: string; // 32 bytes hex
  stateMerkleRootHex: string; // 32 bytes hex
  changeChainHeadHex: string; // 32 bytes hex
  previousCommitmentDigestHex: string; // 32 bytes hex
  commitmentDigestHex: string; // 32 bytes hex
  logicalTimestampUs: bigint;
  protocolVersion: number;
  agentSignatureHex: string;
  customerSignatureHex: string;
}

export interface BesuTransactionReceipt {
  transactionHash: `0x${string}`;
  blockNumber: bigint;
  blockHash: `0x${string}`;
  from: `0x${string}`;
  to: `0x${string}` | null;
  status: 'success' | 'reverted';
  gasUsed: bigint;
  logs: any[];
}

export interface BesuCommitmentResult {
  success: boolean;
  txHash: `0x${string}`;
  blockNumber: bigint;
  blockHash: `0x${string}`;
  commitmentDigestHex: string;
  contractAddress: `0x${string}`;
}
