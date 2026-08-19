import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { EvidenceJournalEntry } from './types.js';
import { decodeBinaryRecord } from '../binary/decoder.js';
import { ChangeRecordData, MutationOperation } from '../protocol/types.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export class DurableEvidenceJournal {
  private filePath?: string;
  private fd?: number;
  private inMemoryEntries: EvidenceJournalEntry[] = [];
  private currentChainHead: Buffer;
  private lastSeq: bigint = 0n;
  private schemaEpoch: number = 1;

  constructor(filePath?: string, initialChainHead: Buffer = Buffer.alloc(32, 0), schemaEpoch: number = 1) {
    this.filePath = filePath;
    this.currentChainHead = Buffer.from(initialChainHead);
    this.schemaEpoch = schemaEpoch;

    if (this.filePath) {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      const fileExisted = fs.existsSync(this.filePath) && fs.statSync(this.filePath).size >= 32;

      if (!fileExisted) {
        const headerBuf = Buffer.alloc(32);
        headerBuf.write('WDB:EV_JRNL:v1\0', 0, 16, 'utf8');
        headerBuf.writeUInt32BE(1, 16); // formatVersion = 1
        headerBuf.writeBigInt64BE(BigInt(Date.now()) * 1000n, 20); // createdAtUs
        headerBuf.writeUInt32BE(this.schemaEpoch, 28); // schemaEpoch
        fs.writeFileSync(this.filePath, headerBuf);
        this.fd = fs.openSync(this.filePath, 'a+');
      } else {
        // Recover state from existing journal file
        const diskEntries = this.readAllFromDisk();
        this.inMemoryEntries = [...diskEntries];
        if (diskEntries.length > 0) {
          const last = diskEntries[diskEntries.length - 1]!;
          this.lastSeq = last.sequenceNumber;
          this.currentChainHead = Buffer.from(last.changeHash);
        }
        this.fd = fs.openSync(this.filePath, 'a+');
      }
    }
  }

  public get chainHead(): Buffer {
    return Buffer.from(this.currentChainHead);
  }

  public get sequence(): bigint {
    return this.lastSeq;
  }

  public get length(): number {
    return this.inMemoryEntries.length;
  }

  /**
   * Appends an evidence entry to the journal with SHA-256 hash chaining and synchronous fsync.
   */
  public async append(entry: EvidenceJournalEntry): Promise<void> {
    // Assert hash chain continuity
    if (!timingSafeEqualHashes(entry.previousHash, this.currentChainHead)) {
      throw new WolverineError(
        WolverineErrorCode.HASH_CHAIN_DISCONTINUITY,
        `Evidence journal hash discontinuity at seq ${entry.sequenceNumber}. Expected previousHash ${this.currentChainHead.toString('hex')}, observed ${entry.previousHash.toString('hex')}`
      );
    }

    if (this.lastSeq > 0n && entry.sequenceNumber !== this.lastSeq + 1n) {
      throw new WolverineError(
        WolverineErrorCode.SEQUENCE_GAP_DETECTED,
        `Evidence journal sequence gap. Expected ${this.lastSeq + 1n}, observed ${entry.sequenceNumber}`
      );
    }

    if (this.fd !== undefined) {
      const framedRecord = this.serializeFramedEntry(entry);
      fs.writeSync(this.fd, framedRecord);
      fs.fsyncSync(this.fd);
    }

    this.inMemoryEntries.push(entry);
    this.lastSeq = entry.sequenceNumber;
    this.currentChainHead = Buffer.from(entry.changeHash);
  }

  /**
   * Replays journal entries sequentially from disk or memory.
   */
  public async replay(fromSeq: bigint = 1n, toSeq?: bigint): Promise<EvidenceJournalEntry[]> {
    if (this.filePath && fs.existsSync(this.filePath)) {
      const diskEntries = this.readAllFromDisk();
      return diskEntries.filter((e) => e.sequenceNumber >= fromSeq && (toSeq === undefined || e.sequenceNumber <= toSeq));
    }

    return this.inMemoryEntries.filter((e) => e.sequenceNumber >= fromSeq && (toSeq === undefined || e.sequenceNumber <= toSeq));
  }

  /**
   * Reads and verifies the entire journal file integrity.
   */
  public async verifyChainIntegrity(): Promise<{ valid: boolean; entryCount: number; lastSeq: bigint; lastHash: Buffer }> {
    const entries = this.filePath && fs.existsSync(this.filePath) ? this.readAllFromDisk() : this.inMemoryEntries;
    let runningHead = Buffer.alloc(32, 0);
    let expectedSeq = 1n;

    for (const entry of entries) {
      if (entry.sequenceNumber !== expectedSeq) {
        throw new WolverineError(
          WolverineErrorCode.SEQUENCE_GAP_DETECTED,
          `Journal verification failed: sequence gap at seq ${entry.sequenceNumber}`
        );
      }

      if (!timingSafeEqualHashes(entry.previousHash, runningHead)) {
        throw new WolverineError(
          WolverineErrorCode.HASH_CHAIN_DISCONTINUITY,
          `Journal verification failed: hash discontinuity at seq ${entry.sequenceNumber}`
        );
      }

      runningHead = Buffer.from(entry.changeHash);
      expectedSeq++;
    }

    return {
      valid: true,
      entryCount: entries.length,
      lastSeq: entries.length > 0 ? entries[entries.length - 1]!.sequenceNumber : 0n,
      lastHash: runningHead,
    };
  }

  public async close(): Promise<void> {
    if (this.fd !== undefined) {
      fs.closeSync(this.fd);
      this.fd = undefined;
    }
  }

  private serializeFramedEntry(entry: EvidenceJournalEntry): Buffer {
    const lsnBuf = Buffer.from(entry.lsn, 'utf8');
    const xidBuf = Buffer.from(entry.xid, 'utf8');
    const recordBytes = entry.recordBytes;

    const payloadLen =
      8 + // sequenceNumber
      8 + // timestampUs
      2 + lsnBuf.length +
      2 + xidBuf.length +
      32 + // previousHash
      32 + // changeHash
      4 + recordBytes.length;

    const buf = Buffer.alloc(4 + 4 + payloadLen + 32);
    let offset = 0;

    // Magic: "WDBE" (0x57 0x44 0x42 0x45)
    buf.write('WDBE', offset, 4, 'utf8');
    offset += 4;

    buf.writeUInt32BE(payloadLen, offset);
    offset += 4;

    const payloadStart = offset;

    buf.writeBigInt64BE(entry.sequenceNumber, offset);
    offset += 8;

    buf.writeBigInt64BE(entry.timestampUs, offset);
    offset += 8;

    buf.writeUInt16BE(lsnBuf.length, offset);
    offset += 2;
    lsnBuf.copy(buf, offset);
    offset += lsnBuf.length;

    buf.writeUInt16BE(xidBuf.length, offset);
    offset += 2;
    xidBuf.copy(buf, offset);
    offset += xidBuf.length;

    entry.previousHash.copy(buf, offset);
    offset += 32;

    entry.changeHash.copy(buf, offset);
    offset += 32;

    buf.writeUInt32BE(recordBytes.length, offset);
    offset += 4;
    recordBytes.copy(buf, offset);
    offset += recordBytes.length;

    // Compute checksum over payload
    const payloadSlice = buf.subarray(payloadStart, offset);
    const checksum = crypto.createHash('sha256').update(payloadSlice).digest();
    checksum.copy(buf, offset);

    return buf;
  }

  private readAllFromDisk(): EvidenceJournalEntry[] {
    if (!this.filePath || !fs.existsSync(this.filePath)) {
      return [];
    }

    const fileBuf = fs.readFileSync(this.filePath);
    if (fileBuf.length < 32) return [];

    const magic = fileBuf.subarray(0, 15).toString('utf8');
    if (!magic.startsWith('WDB:EV_JRNL')) {
      throw new WolverineError(
        WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
        'Invalid evidence journal file magic header'
      );
    }

    const entries: EvidenceJournalEntry[] = [];
    let offset = 32;

    while (offset < fileBuf.length) {
      if (offset + 8 > fileBuf.length) break;

      const tag = fileBuf.subarray(offset, offset + 4).toString('utf8');
      if (tag !== 'WDBE') {
        throw new WolverineError(
          WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
          `Invalid evidence entry framing tag at offset ${offset}`
        );
      }
      offset += 4;

      const payloadLen = fileBuf.readUInt32BE(offset);
      offset += 4;

      if (offset + payloadLen + 32 > fileBuf.length) {
        // Truncated trailing write during crash
        break;
      }

      const payloadBuf = fileBuf.subarray(offset, offset + payloadLen);
      const storedChecksum = fileBuf.subarray(offset + payloadLen, offset + payloadLen + 32);
      const computedChecksum = crypto.createHash('sha256').update(payloadBuf).digest();

      if (!timingSafeEqualHashes(storedChecksum, computedChecksum)) {
        throw new WolverineError(
          WolverineErrorCode.CHECKSUM_MISMATCH,
          `Checksum mismatch in evidence journal at offset ${offset}`
        );
      }

      let pOff = 0;
      const sequenceNumber = payloadBuf.readBigInt64BE(pOff);
      pOff += 8;

      const timestampUs = payloadBuf.readBigInt64BE(pOff);
      pOff += 8;

      const lsnLen = payloadBuf.readUInt16BE(pOff);
      pOff += 2;
      const lsn = payloadBuf.subarray(pOff, pOff + lsnLen).toString('utf8');
      pOff += lsnLen;

      const xidLen = payloadBuf.readUInt16BE(pOff);
      pOff += 2;
      const xid = payloadBuf.subarray(pOff, pOff + xidLen).toString('utf8');
      pOff += xidLen;

      const previousHash = Buffer.from(payloadBuf.subarray(pOff, pOff + 32));
      pOff += 32;

      const changeHash = Buffer.from(payloadBuf.subarray(pOff, pOff + 32));
      pOff += 32;

      const recordBytesLen = payloadBuf.readUInt32BE(pOff);
      pOff += 4;
      const recordBytes = Buffer.from(payloadBuf.subarray(pOff, pOff + recordBytesLen));

      const changeRecord = this.decodeChangeRecordFromBinary(recordBytes, previousHash);

      entries.push({
        sequenceNumber,
        lsn,
        xid,
        timestampUs,
        changeRecord,
        recordBytes,
        changeHash,
        previousHash,
      });

      offset += payloadLen + 32;
    }

    return entries;
  }

  private decodeChangeRecordFromBinary(recordBytes: Buffer, previousHash: Buffer): ChangeRecordData {
    const decoded = decodeBinaryRecord(recordBytes);
    const tag1 = decoded.getFieldByTag(1);
    const tag2 = decoded.getFieldByTag(2);
    const tag3 = decoded.getFieldByTag(3);
    const tag4 = decoded.getFieldByTag(4);
    const tag5 = decoded.getFieldByTag(5);
    const tag6 = decoded.getFieldByTag(6);
    const tag7 = decoded.getFieldByTag(7);
    const tag8 = decoded.getFieldByTag(8);
    const tag9 = decoded.getFieldByTag(9);

    const formatVersion = tag1 ? Number(tag1.payload.readBigUInt64BE(0)) : 1;
    const versionId = tag2
      ? [
          tag2.payload.subarray(0, 4).toString('hex'),
          tag2.payload.subarray(4, 6).toString('hex'),
          tag2.payload.subarray(6, 8).toString('hex'),
          tag2.payload.subarray(8, 10).toString('hex'),
          tag2.payload.subarray(10, 16).toString('hex'),
        ].join('-')
      : '00000000-0000-0000-0000-000000000001';

    const transactionId = tag3 ? tag3.payload.toString('utf8') : 'tx:unknown';
    const timestampUs = tag4 ? tag4.payload.readBigInt64BE(0) : 0n;
    const tableId = tag5 ? tag5.payload.toString('utf8') : 'public.unknown';
    const recordId = tag6 ? tag6.payload : Buffer.alloc(0);
    const operation = tag7 ? (Number(tag7.payload.readBigUInt64BE(0)) as MutationOperation) : MutationOperation.INSERT;
    const fieldSet = tag8 ? JSON.parse(tag8.payload.toString('utf8')) : {};
    const provenance = tag9 ? JSON.parse(tag9.payload.toString('utf8')) : {};

    return {
      formatVersion,
      versionId,
      transactionId,
      timestampUs,
      tableId,
      recordId,
      operation,
      fieldSet,
      provenance,
      previousHash,
    };
  }
}
