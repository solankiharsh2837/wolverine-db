import {
  TrustLedgerRecord,
  TrustLedgerRecordType,
} from '../trust_network/types.js';
import { computeLedgerRecordDigest } from '../trust_network/ledger.js';
import { MerkleTree, EMPTY_TREE_ROOT } from '../crypto/merkle.js';
import { IPersistentStorage, LedgerStateRootSnapshot } from './types.js';

export class MemoryJournalStorage implements IPersistentStorage {
  private records: TrustLedgerRecord[] = [];

  public async writeRecord(record: TrustLedgerRecord): Promise<void> {
    this.records.push(record);
  }

  public async readAllRecords(): Promise<TrustLedgerRecord[]> {
    return [...this.records];
  }

  public async clear(): Promise<void> {
    this.records = [];
  }
}

export class PersistentTrustLedger {
  private storage: IPersistentStorage;
  private records: TrustLedgerRecord[] = [];
  private chainHead: Buffer = Buffer.alloc(32, 0);
  private recordDigests: Buffer[] = [];
  private isRecovered: boolean = false;
  private appendMutex: Promise<any> = Promise.resolve();

  constructor(storage?: IPersistentStorage) {
    this.storage = storage ?? new MemoryJournalStorage();
  }

  public async init(): Promise<void> {
    if (this.isRecovered) return;
    const stored = await this.storage.readAllRecords();
    for (const rec of stored) {
      this.records.push(rec);
      this.recordDigests.push(rec.recordDigest);
      this.chainHead = rec.recordDigest;
    }
    this.isRecovered = true;
  }

  /**
   * Appends a record to the persistent ledger with strict linearizable atomic serialization.
   */
  public async appendRecord(
    recordType: TrustLedgerRecordType,
    payload: Record<string, unknown>,
    epoch: number = 1,
    validatorSetId: string = 'valset-genesis',
    tenantId?: string | undefined,
    databaseId?: string | undefined
  ): Promise<TrustLedgerRecord> {
    const executeAppend = async (): Promise<TrustLedgerRecord> => {
      if (!this.isRecovered) {
        await this.init();
      }

      const ledgerSeq = BigInt(this.records.length + 1);
      const previousRecordDigest = this.chainHead;
      const timestampUs = BigInt(Date.now()) * 1000n;

      const recordDigest = computeLedgerRecordDigest(
        previousRecordDigest,
        ledgerSeq,
        payload
      );

      const record: TrustLedgerRecord = {
        ledgerSeq,
        previousRecordDigest,
        recordDigest,
        recordType,
        payload,
        epoch,
        validatorSetId,
        timestampUs,
        tenantId,
        databaseId,
      };

      // Commit to persistent storage before updating in-memory state
      await this.storage.writeRecord(record);

      this.records.push(record);
      this.recordDigests.push(recordDigest);
      this.chainHead = recordDigest;

      return record;
    };

    // Serialize all concurrent append operations through the mutex queue
    const nextAppend = this.appendMutex.then(executeAppend, executeAppend);
    this.appendMutex = nextAppend;
    return nextAppend;
  }

  public getRecords(): TrustLedgerRecord[] {
    return [...this.records];
  }

  public getRecord(ledgerSeq: bigint): TrustLedgerRecord | undefined {
    return this.records.find((r) => r.ledgerSeq === ledgerSeq);
  }

  public getChainHead(): Buffer {
    return this.chainHead;
  }

  /**
   * Verifies the cryptographic integrity of the entire ledger chain.
   */
  public verifyLedgerIntegrity(): boolean {
    if (this.records.length === 0) return true;

    for (let i = 0; i < this.records.length; i++) {
      const rec = this.records[i]!;
      const expectedPrev = i === 0 ? Buffer.alloc(32, 0) : this.records[i - 1]!.recordDigest;

      if (Buffer.compare(rec.previousRecordDigest, expectedPrev) !== 0) {
        return false;
      }

      const recomputed = computeLedgerRecordDigest(
        rec.previousRecordDigest,
        rec.ledgerSeq,
        rec.payload
      );

      if (Buffer.compare(recomputed, rec.recordDigest) !== 0) {
        return false;
      }
    }
    return true;
  }

  /**
   * Computes the incremental 32-byte Merkle State Root of the ledger records.
   */
  public computeMerkleStateRoot(): Buffer {
    if (this.recordDigests.length === 0) {
      return EMPTY_TREE_ROOT;
    }
    const tree = new MerkleTree(this.recordDigests);
    return tree.root;
  }

  public getMerkleStateRoot(): Buffer {
    return this.computeMerkleStateRoot();
  }

  /**
   * Generates a point-in-time state root snapshot for cross-replica sync.
   */
  public generateStateRootSnapshot(): LedgerStateRootSnapshot {
    return {
      ledgerSeq: BigInt(this.records.length),
      recordCount: this.records.length,
      merkleStateRoot: this.computeMerkleStateRoot(),
      chainHeadDigest: this.chainHead,
      timestampUs: BigInt(Date.now()) * 1000n,
    };
  }

  public getStateRootSnapshot(): LedgerStateRootSnapshot {
    return this.generateStateRootSnapshot();
  }
}
