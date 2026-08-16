import crypto from 'node:crypto';
import {
  TrustCommitment,
  PortableTrustProof,
  OfflineProofVerificationResult,
} from '../trust_network/types.js';
import { createSignedCustomerCommitment } from '../trust_network/commitment.js';
import { OfflineTrustProofVerifier } from '../trust_network/proof.js';
import { TrustGatewayServer } from './gateway.js';
import { AnchoredCheckpoint } from '../checkpoint/types.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface EvidenceAgentClientConfig {
  tenantId: string;
  databaseId: string;
  customerPubkey: Buffer;
  customerPrivateKey: crypto.KeyObject;
  gateway: TrustGatewayServer;
}

export class WolverineEvidenceAgentClient {
  private tenantId: string;
  private databaseId: string;
  private customerPubkey: Buffer;
  private customerPrivateKey: crypto.KeyObject;
  private gateway: TrustGatewayServer;

  private lastCommitmentDigest: Buffer = Buffer.alloc(32, 0);
  private localProofCache = new Map<string, PortableTrustProof>();
  private offlineQueue: TrustCommitment[] = [];

  constructor(config: EvidenceAgentClientConfig) {
    if (!config.customerPrivateKey) {
      throw new WolverineError(
        WolverineErrorCode.MISSING_SECRET_KEY,
        'Evidence agent client requires customerPrivateKey for signing commitments'
      );
    }
    this.tenantId = config.tenantId;
    this.databaseId = config.databaseId;
    this.customerPubkey = config.customerPubkey;
    this.customerPrivateKey = config.customerPrivateKey;
    this.gateway = config.gateway;
  }

  public async commitCheckpoint(
    checkpoint: AnchoredCheckpoint | Omit<AnchoredCheckpoint, 'digest'>,
    checkpointDigest: Buffer
  ): Promise<{
    commitment: TrustCommitment;
    isSynchronized: boolean;
    proof?: PortableTrustProof | undefined;
  }> {
    const commitmentId = crypto.randomUUID();

    const commitment = createSignedCustomerCommitment(
      {
        commitmentId,
        tenantId: this.tenantId,
        databaseId: this.databaseId,
        checkpointId: checkpoint.checkpointId,
        commitSeq: checkpoint.commitSeq,
        checkpointDigest,
        previousTrustCommitment: this.lastCommitmentDigest,
      },
      this.customerPrivateKey,
      this.customerPubkey
    );

    this.lastCommitmentDigest = commitment.commitmentDigest;

    // Attempt submission to Trust Gateway
    try {
      await this.flushQueue();

      const result = await this.gateway.ingestCommitment(commitment);
      this.localProofCache.set(checkpoint.checkpointId, result.proof);
      return {
        commitment,
        isSynchronized: true,
        proof: result.proof,
      };
    } catch (err: any) {
      if (
        err instanceof WolverineError &&
        (err.code === WolverineErrorCode.ANCHOR_UNAVAILABLE || err.message.includes('offline'))
      ) {
        this.offlineQueue.push(commitment);
        return {
          commitment,
          isSynchronized: false,
        };
      }
      throw err;
    }
  }

  public async flushQueue(): Promise<number> {
    if (this.offlineQueue.length === 0) return 0;

    let processed = 0;
    while (this.offlineQueue.length > 0) {
      const item = this.offlineQueue[0]!;
      const result = await this.gateway.ingestCommitment(item);
      this.localProofCache.set(item.checkpointId, result.proof);
      this.offlineQueue.shift();
      processed++;
    }
    return processed;
  }

  public getOfflineQueueLength(): number {
    return this.offlineQueue.length;
  }

  public getCachedProof(checkpointId: string): PortableTrustProof | null {
    return this.localProofCache.get(checkpointId) || null;
  }

  public verifyProofOffline(proof: PortableTrustProof): OfflineProofVerificationResult {
    return OfflineTrustProofVerifier.verifyPortableProof(proof);
  }
}
