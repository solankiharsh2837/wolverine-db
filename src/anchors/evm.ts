import crypto from 'node:crypto';
import { EvmAnchorConfig, AnchorRecord, AnchorDomainType, AnchorStatus } from './types.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export class EvmAnchorAdapter {
  public readonly config: EvmAnchorConfig;
  private onChainRegistry = new Map<string, AnchorRecord>();
  private currentBlockNumber = 1000n;
  private isRpcOnline = true;

  constructor(config: EvmAnchorConfig) {
    this.config = config;
  }

  public setRpcOnline(status: boolean): void {
    this.isRpcOnline = status;
  }

  public advanceBlock(count = 1n): bigint {
    this.currentBlockNumber += count;
    this.updateConfirmations();
    return this.currentBlockNumber;
  }

  /**
   * Simulates a blockchain reorg, unwinding blocks and resetting confirmation status.
   */
  public triggerReorg(reorgDepth: bigint): void {
    this.currentBlockNumber -= reorgDepth;
    for (const record of this.onChainRegistry.values()) {
      if (record.blockNumber && record.blockNumber > this.currentBlockNumber) {
        record.status = AnchorStatus.ORPHANED_REORG;
        record.confirmationCount = 0;
      }
    }
  }

  private updateConfirmations(): void {
    for (const record of this.onChainRegistry.values()) {
      if (record.blockNumber && record.status !== AnchorStatus.FAILED) {
        const confirmations = Number(this.currentBlockNumber - record.blockNumber + 1n);
        record.confirmationCount = Math.max(0, confirmations);
        if (record.confirmationCount >= record.requiredConfirmations) {
          record.status = AnchorStatus.FINALIZED;
        } else if (record.confirmationCount > 0) {
          record.status = AnchorStatus.CONFIRMING;
        }
      }
    }
  }

  /**
   * Publishes a checkpoint digest to the EVM anchor registry.
   */
  public async anchorCheckpoint(
    checkpointId: string,
    checkpointDigest: Buffer,
    commitSeq: bigint,
    currentGasPriceGwei = 20
  ): Promise<AnchorRecord> {
    if (!this.isRpcOnline) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_UNAVAILABLE,
        `EVM RPC endpoint unreachable for chainId ${this.config.chainId}`
      );
    }

    if (this.config.maxGasPriceGwei && currentGasPriceGwei > this.config.maxGasPriceGwei) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_UNAVAILABLE,
        `Current gas price (${currentGasPriceGwei} Gwei) exceeds max configured limit (${this.config.maxGasPriceGwei} Gwei)`
      );
    }

    // Check if anchor already exists on-chain
    if (this.onChainRegistry.has(checkpointId)) {
      const existing = this.onChainRegistry.get(checkpointId)!;
      if (!timingSafeEqualHashes(existing.checkpointDigest, checkpointDigest)) {
        throw new WolverineError(
          WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
          `ConflictingAnchorCommitmentError: Checkpoint ${checkpointId} is already anchored on-chain with differing digest`
        );
      }
      return existing; // Idempotent OK
    }

    const timestampUs = BigInt(Date.now()) * 1000n;
    const txHash = '0x' + crypto.randomBytes(32).toString('hex');
    const blockNumber = this.currentBlockNumber;

    const record: AnchorRecord = {
      anchorId: `evm-${this.config.chainId}-${checkpointId.slice(0, 8)}`,
      domainType: AnchorDomainType.EVM,
      chainId: this.config.chainId,
      checkpointId,
      checkpointDigest,
      commitSeq,
      status: this.config.requiredConfirmations <= 1 ? AnchorStatus.FINALIZED : AnchorStatus.CONFIRMING,
      blockNumber,
      transactionHash: txHash,
      confirmationCount: 1,
      requiredConfirmations: this.config.requiredConfirmations,
      timestampUs,
    };

    this.onChainRegistry.set(checkpointId, record);
    return record;
  }

  /**
   * Retrieves an on-chain anchor commitment.
   */
  public async getAnchor(checkpointId: string): Promise<AnchorRecord | null> {
    if (!this.isRpcOnline) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_UNAVAILABLE,
        `EVM RPC endpoint unreachable for chainId ${this.config.chainId}`
      );
    }
    return this.onChainRegistry.get(checkpointId) || null;
  }
}
