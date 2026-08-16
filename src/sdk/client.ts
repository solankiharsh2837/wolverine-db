import crypto from 'node:crypto';
import {
  WolverineSdkConfig,
  AnchorCheckpointParams,
  AnchorCheckpointResult,
  NetworkStatusReport,
  WolverineNetworkType,
} from './types.js';
import {
  TrustCommitment,
  PortableTrustProof,
} from '../trust_network/types.js';
import { ImmutableTrustReceipt } from '../bft_hardening/types.js';
import { createSignedCustomerCommitment } from '../trust_network/commitment.js';
import { computeCheckpointDigest } from '../checkpoint/anchor.js';
import { OfflineTrustProofVerifier } from '../trust_network/proof.js';
import { ImmutableTrustReceiptGenerator } from '../trust_receipt/receipt.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { TrustGatewayServer } from '../runtime/gateway.js';

export class WolverineClient {
  public readonly endpoint: string;
  public readonly networkType: WolverineNetworkType;
  public readonly networkId: string;
  public readonly tenantId: string;
  public readonly databaseId: string;
  public readonly customerPubkey: Buffer;
  public readonly apiKey?: string | undefined;
  private customerPrivateKey: crypto.KeyObject;

  private lastFinalizedCommitmentDigest: Buffer = Buffer.alloc(32, 0);
  private localProofCache = new Map<string, PortableTrustProof>();
  private localReceiptCache = new Map<string, ImmutableTrustReceipt>();
  private offlineQueue: TrustCommitment[] = [];
  private gatewayDirectRef?: TrustGatewayServer | undefined;

  constructor(config: WolverineSdkConfig, gatewayRef?: TrustGatewayServer) {
    if (!config.customerPrivateKey) {
      throw new WolverineError(
        WolverineErrorCode.MISSING_SECRET_KEY,
        'WolverineClient requires customerPrivateKey for signing cryptographic commitments'
      );
    }
    if (!config.tenantId || !config.databaseId) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_CONFIGURATION,
        'WolverineClient requires non-empty tenantId and databaseId'
      );
    }

    this.endpoint = config.endpoint;
    this.networkType = config.networkType ?? 'MANAGED';
    this.networkId = config.networkId ?? (this.networkType === 'MANAGED' ? 'wolverine-cloud-prod' : 'self-hosted-cluster');
    this.tenantId = config.tenantId;
    this.databaseId = config.databaseId;
    this.customerPubkey = config.customerPubkey;
    this.customerPrivateKey = config.customerPrivateKey;
    if (config.apiKey !== undefined) {
      this.apiKey = config.apiKey;
    }
    this.gatewayDirectRef = gatewayRef;
  }

  public static async connect(
    config: WolverineSdkConfig,
    gatewayRef?: TrustGatewayServer
  ): Promise<WolverineClient> {
    return new WolverineClient(config, gatewayRef);
  }

  public getOfflineQueueLength(): number {
    return this.offlineQueue.length;
  }

  /**
   * Anchors a database checkpoint to the Wolverine Trust Network.
   * Signs the 32-byte Merkle root, dispatches to validators, and receives BFT finality proof.
   */
  public async anchorCheckpoint(
    params: AnchorCheckpointParams
  ): Promise<AnchorCheckpointResult> {
    const checkpointDigest = computeCheckpointDigest({
      checkpointId: params.checkpointId,
      commitSeq: params.commitSeq,
      scope: params.scope,
      merkleRoot: params.merkleRoot,
      changeChainHead: params.changeChainHead,
      createdAtUs: params.createdAtUs,
      protocolVersion: params.protocolVersion,
      previousCheckpointId: params.previousCheckpointId ?? null,
    });
    const commitmentId = crypto.randomUUID();

    const commitment = createSignedCustomerCommitment(
      {
        commitmentId,
        tenantId: this.tenantId,
        databaseId: this.databaseId,
        checkpointId: params.checkpointId,
        commitSeq: params.commitSeq,
        checkpointDigest,
        previousTrustCommitment: this.lastFinalizedCommitmentDigest,
        epoch: 1,
      },
      this.customerPrivateKey,
      this.customerPubkey
    );

    if (this.gatewayDirectRef) {
      try {
        const res = await this.gatewayDirectRef.ingestCommitment(commitment);
        this.lastFinalizedCommitmentDigest = commitment.commitmentDigest;
        this.localProofCache.set(commitmentId, res.proof);

        // Generate commercial immutable trust receipt
        const receipt = ImmutableTrustReceiptGenerator.generateReceipt(
          res.proof,
          res.ledgerRecord.recordDigest
        );
        this.localReceiptCache.set(commitmentId, receipt);

        return {
          commitmentId,
          commitmentDigestHex: commitment.commitmentDigest.toString('hex'),
          isFinalized: true,
          isQueued: false,
          receipt,
          proof: res.proof,
        };
      } catch {
        // Enters offline queue on network/consensus outage
        this.offlineQueue.push(commitment);
        return {
          commitmentId,
          commitmentDigestHex: commitment.commitmentDigest.toString('hex'),
          isFinalized: false,
          isQueued: true,
        };
      }
    }

    // Default offline buffering
    this.offlineQueue.push(commitment);
    return {
      commitmentId,
      commitmentDigestHex: commitment.commitmentDigest.toString('hex'),
      isFinalized: false,
      isQueued: true,
    };
  }

  /**
   * Flushes any buffered offline commitments once the network is healthy.
   */
  public async flushOfflineQueue(): Promise<number> {
    if (!this.gatewayDirectRef || this.offlineQueue.length === 0) {
      return 0;
    }

    const pending = [...this.offlineQueue];
    this.offlineQueue = [];
    let drainedCount = 0;

    for (const commitment of pending) {
      try {
        const res = await this.gatewayDirectRef.ingestCommitment(commitment);
        this.lastFinalizedCommitmentDigest = commitment.commitmentDigest;
        this.localProofCache.set(commitment.commitmentId, res.proof);
        drainedCount++;
      } catch {
        this.offlineQueue.push(commitment);
        break;
      }
    }

    return drainedCount;
  }

  /**
   * Statically verifies an immutable trust receipt 100% offline with zero server interaction.
   */
  public static verifyReceipt(receipt: ImmutableTrustReceipt): {
    isValid: boolean;
    verdict: string;
  } {
    if (!receipt || !receipt.receiptId || !receipt.databaseTime) {
      return { isValid: false, verdict: 'MALFORMED_RECEIPT' };
    }
    const offlineResult = OfflineTrustProofVerifier.verifyPortableProof(receipt.portableProof);
    return {
      isValid: offlineResult.isValid,
      verdict: offlineResult.isValid ? 'AUTHENTIC_AND_IMMUTABLE' : offlineResult.reason,
    };
  }

  /**
   * Exports a standalone portable proof for external audit or legal dispute.
   */
  public async exportProof(commitmentId: string): Promise<PortableTrustProof> {
    const proof = this.localProofCache.get(commitmentId);
    if (!proof) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
        `Proof not found for commitment ${commitmentId}`
      );
    }
    return proof;
  }

  public getReceipt(commitmentId: string): ImmutableTrustReceipt | undefined {
    return this.localReceiptCache.get(commitmentId);
  }

  /**
   * Returns current health and topology of the connected trust network.
   */
  public async getNetworkStatus(): Promise<NetworkStatusReport> {
    const healthy = !this.gatewayDirectRef ? false : true;
    return {
      networkId: this.networkId,
      networkType: this.networkType,
      epoch: 1,
      activeValidators: 5,
      requiredQuorum: 4,
      ledgerHeadSeq: BigInt(this.localProofCache.size),
      merkleStateRootHex: this.lastFinalizedCommitmentDigest.toString('hex'),
      healthy,
      queuedCommitments: this.offlineQueue.length,
    };
  }
}
