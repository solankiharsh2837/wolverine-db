import crypto from 'node:crypto';
import {
  TrustCommitment,
  PortableTrustProof,
  OfflineProofVerificationResult,
} from './types.js';
import { createSignedCustomerCommitment } from './commitment.js';
import { WolverineTrustNetworkService } from './service.js';
import { OfflineTrustProofVerifier } from './proof.js';
import { AnchoredCheckpoint } from '../checkpoint/types.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface AgentConfig {
  tenantId: string;
  databaseId: string;
  customerPubkey: Buffer;
  customerPrivateKey: crypto.KeyObject;
  service: WolverineTrustNetworkService;
}

export class WolverineEvidenceAgent {
  private tenantId: string;
  private databaseId: string;
  private customerPubkey: Buffer;
  private customerPrivateKey: crypto.KeyObject;
  private service: WolverineTrustNetworkService;

  private lastCommitmentDigest: Buffer = Buffer.alloc(32, 0);
  private localProofCache = new Map<string, PortableTrustProof>();
  private offlineQueue: TrustCommitment[] = [];

  constructor(config: AgentConfig) {
    this.tenantId = config.tenantId;
    this.databaseId = config.databaseId;
    this.customerPubkey = config.customerPubkey;
    this.customerPrivateKey = config.customerPrivateKey;
    this.service = config.service;
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

    // Attempt submission
    try {
      // First flush any pending queue
      await this.flushQueue();

      const result = await this.service.submitCommitment(commitment);
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
        // Offline fallback: Queue locally
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
      const result = await this.service.submitCommitment(item);
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
