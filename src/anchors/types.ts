export enum AnchorDomainType {
  EVM = 1,
  BITCOIN_OP_RETURN = 2,
  RFC6962_TRANSPARENCY_LOG = 3,
  RFC3161_TIMESTAMP_AUTHORITY = 4,
}

export enum AnchorStatus {
  PENDING = 'PENDING',
  CONFIRMING = 'CONFIRMING',
  FINALIZED = 'FINALIZED',
  ORPHANED_REORG = 'ORPHANED_REORG',
  FAILED = 'FAILED',
}

export interface AnchorRecord {
  anchorId: string;
  domainType: AnchorDomainType;
  chainId: string;
  checkpointId: string;
  checkpointDigest: Buffer; // 32 bytes SHA-256
  commitSeq: bigint;
  status: AnchorStatus;
  blockNumber?: bigint;
  transactionHash?: string;
  confirmationCount: number;
  requiredConfirmations: number;
  timestampUs: bigint;
}

export interface EvmAnchorConfig {
  chainId: string; // e.g. "1" (Mainnet), "8453" (Base), "42161" (Arbitrum)
  contractAddress: string;
  rpcUrl?: string;
  requiredConfirmations: number;
  maxGasPriceGwei?: number;
  mockClient?: boolean;
}

export interface ConsensusPolicy {
  requiredQuorum: number; // M
  totalAnchors: number;   // N
  minimumFinalizedAnchors?: number;
}

export type ConsensusVerdict =
  | 'CONSENSUS_VALID'
  | 'CONSENSUS_SUSPICIOUS'
  | 'CONSENSUS_DIVERGENCE'
  | 'CONSENSUS_INDETERMINATE';

export interface ConsensusReport {
  verdict: ConsensusVerdict;
  matchingCount: number;
  totalEvaluated: number;
  requiredQuorum: number;
  anchorResults: Array<{
    anchorId: string;
    chainId: string;
    status: AnchorStatus;
    matches: boolean;
    digestHex: string;
  }>;
  summaryMessage: string;
}
