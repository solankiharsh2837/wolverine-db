import {
  TrustLedgerRecord,
  TrustLedgerRecordType,
} from '../trust_network/types.js';
import { computeLedgerRecordDigest } from '../trust_network/ledger.js';
import { MerkleTree } from '../crypto/merkle.js';
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

  public async appendRecord(
    recordType: TrustLedgerRecordType,
    payload: Record<string, unknown>,
    epoch: number = 1,
    validatorSetId: string = 'valset-genesis',
    tenantId?: string | undefined,
    databaseId?: string | undefined
  ): Promise<TrustLedgerRecord> {
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

    // Commit to persistent storage
    await this.storage.writeRecord(record);

    this.records.push(record);
    this.recordDigests.push(recordDigest);
    this.chainHead = recordDigest;

    return record;
  }

  public getMerkleStateRoot(): Buffer {
    if (this.recordDigests.length === 0) {
      return Buffer.alloc(32, 0);
    }
    const tree = new MerkleTree(this.recordDigests);
    return tree.root;
  }

  public getStateRootSnapshot(): LedgerStateRootSnapshot {
    return {
      ledgerSeq: BigInt(this.records.length),
      recordCount: this.records.length,
      merkleStateRoot: this.getMerkleStateRoot(),
      chainHeadDigest: this.chainHead,
      timestampUs: BigInt(Date.now()) * 1000n,
    };
  }

  public getRecords(): TrustLedgerRecord[] {
    return [...this.records];
  }

  public verifyLedgerIntegrity(): boolean {
    let prev = Buffer.alloc(32, 0);
    for (let i = 0; i < this.records.length; i++) {
      const rec = this.records[i]!;
      if (Buffer.compare(rec.previousRecordDigest, prev) !== 0) {
        return false;
      }
      const expectedDigest = computeLedgerRecordDigest(
        rec.previousRecordDigest,
        rec.ledgerSeq,
        rec.payload
      );
      if (Buffer.compare(rec.recordDigest, expectedDigest) !== 0) {
        return false;
      }
      prev = Buffer.from(rec.recordDigest);
    }
    return true;
  }
}
