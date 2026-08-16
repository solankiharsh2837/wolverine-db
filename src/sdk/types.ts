import crypto from 'node:crypto';
import {
  PortableTrustProof,
} from '../trust_network/types.js';
import { ImmutableTrustReceipt } from '../bft_hardening/types.js';
import { ISigningProvider } from '../crypto/signing_provider.js';

export type WolverineNetworkType = 'MANAGED' | 'SELF_HOSTED';

export interface WolverineSdkConfig {
  endpoint: string;
  networkType?: WolverineNetworkType;
  networkId?: string;
  tenantId: string;
  databaseId: string;
  signingProvider?: ISigningProvider;
  customerPubkey?: Buffer;
  customerPrivateKey?: crypto.KeyObject;
  apiKey?: string;
  offlineQueueCapacity?: number;
  retryAttempts?: number;
  retryBackoffMs?: number;
}

export interface AnchorCheckpointParams {
  checkpointId: string;
  commitSeq: bigint;
  scope: string;
  merkleRoot: Buffer;
  changeChainHead: Buffer;
  createdAtUs: bigint;
  protocolVersion: number;
  previousCheckpointId?: string | null;
}

export interface AnchorCheckpointResult {
  commitmentId: string;
  commitmentDigestHex: string;
  isFinalized: boolean;
  isQueued: boolean;
  receipt?: ImmutableTrustReceipt | undefined;
  proof?: PortableTrustProof | undefined;
}

export interface NetworkStatusReport {
  networkId: string;
  networkType: WolverineNetworkType;
  epoch: number;
  activeValidators: number;
  requiredQuorum: number;
  ledgerHeadSeq: bigint;
  merkleStateRootHex: string;
  healthy: boolean;
  queuedCommitments: number;
}
