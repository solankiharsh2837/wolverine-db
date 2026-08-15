import { EventEmitter } from 'node:events';
import { WalReceiverConfig, WalAcknowledgment } from './types.js';
import { WalDecoder } from './decoder.js';
import { WalNormalizer, NormalizedWalChange } from './normalizer.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export class WalReceiver extends EventEmitter {
  private config: WalReceiverConfig;
  private decoder: WalDecoder;
  private normalizer: WalNormalizer;
  private isStreaming = false;
  private lastConfirmedFlushLsn: string = '0/0';
  private processedXids = new Set<string>();

  constructor(config: WalReceiverConfig) {
    super();
    this.config = config;
    this.decoder = new WalDecoder();
    this.normalizer = new WalNormalizer();
    if (config.startLsn) {
      this.lastConfirmedFlushLsn = config.startLsn;
    }
  }

  public get confirmedLsn(): string {
    return this.lastConfirmedFlushLsn;
  }

  public get isRunning(): boolean {
    return this.isStreaming;
  }

  /**
   * Starts logical replication consumption.
   */
  public async start(): Promise<void> {
    this.isStreaming = true;
    this.emit('started', { slotName: this.config.slotName, startLsn: this.lastConfirmedFlushLsn });
  }

  /**
   * Stops logical replication streaming safely.
   */
  public async stop(): Promise<void> {
    this.isStreaming = false;
    this.decoder.reset();
    this.emit('stopped');
  }

  /**
   * Simulates/processes incoming raw WAL stream chunks or lines.
   */
  public ingestStreamData(
    rawText: string,
    currentChainHead: Buffer,
    currentVersionId: string = '00000000-0000-0000-0000-000000000001'
  ): NormalizedWalChange[] {
    if (!this.isStreaming) {
      throw new WolverineError(
        WolverineErrorCode.DATABASE_CONNECTION_ERROR,
        'Cannot ingest WAL data while receiver is stopped'
      );
    }

    const lines = rawText.split('\n');
    const allNormalizedChanges: NormalizedWalChange[] = [];

    for (const line of lines) {
      const block = this.decoder.processLine(line);
      if (block) {
        // Deduplicate transaction if already committed
        if (this.processedXids.has(block.xid)) {
          continue;
        }

        const normalized = this.normalizer.normalizeTransaction(
          block,
          currentVersionId,
          currentChainHead,
          this.config.protectedTables
        );

        this.processedXids.add(block.xid);
        if (block.commitLsn && block.commitLsn !== '0/0') {
          this.lastConfirmedFlushLsn = block.commitLsn;
        }

        allNormalizedChanges.push(...normalized);
        this.emit('transaction', { block, changes: normalized });
      }
    }

    return allNormalizedChanges;
  }

  /**
   * Acknowledges flushed LSN back to PostgreSQL replication slot.
   */
  public acknowledgeLsn(flushLsn: string): WalAcknowledgment {
    this.lastConfirmedFlushLsn = flushLsn;
    const ack: WalAcknowledgment = {
      confirmedFlushLsn: flushLsn,
      timestampUs: BigInt(Date.now()) * 1000n,
    };
    this.emit('acknowledged', ack);
    return ack;
  }
}
