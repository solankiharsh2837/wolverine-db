import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { SequenceLockRecord } from './validator_lock.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export class ValidatorDurableJournal {
  private filePath?: string;
  private fd?: number;
  private validatorId: string;
  private inMemoryRecords: SequenceLockRecord[] = [];

  constructor(validatorId: string, filePath?: string) {
    this.validatorId = validatorId;
    this.filePath = filePath;

    if (this.filePath) {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      const fileExisted = fs.existsSync(this.filePath) && fs.statSync(this.filePath).size >= 32;

      if (!fileExisted) {
        const headerBuf = Buffer.alloc(32);
        headerBuf.write('WDB:VAL_JRNL:v1\0', 0, 16, 'utf8');
        headerBuf.writeUInt32BE(1, 16);
        headerBuf.writeBigInt64BE(BigInt(Date.now()) * 1000n, 20);
        fs.writeFileSync(this.filePath, headerBuf);
        this.fd = fs.openSync(this.filePath, 'a+');
      } else {
        const diskRecords = this.readAllFromDisk();
        this.inMemoryRecords = [...diskRecords];
        this.fd = fs.openSync(this.filePath, 'a+');
      }
    }
  }

  public async appendLock(record: SequenceLockRecord): Promise<void> {
    if (this.fd !== undefined) {
      const framed = this.serializeFramedLock(record);
      fs.writeSync(this.fd, framed);
      fs.fsyncSync(this.fd);
    }
    this.inMemoryRecords.push({ ...record });
  }

  public async replay(): Promise<SequenceLockRecord[]> {
    if (this.filePath && fs.existsSync(this.filePath)) {
      return this.readAllFromDisk();
    }
    return [...this.inMemoryRecords];
  }

  public async close(): Promise<void> {
    if (this.fd !== undefined) {
      fs.closeSync(this.fd);
      this.fd = undefined;
    }
  }

  private serializeFramedLock(record: SequenceLockRecord): Buffer {
    const tenantBuf = Buffer.from(record.tenantId, 'utf8');
    const dbBuf = Buffer.from(record.databaseId, 'utf8');
    const digestBuf = Buffer.from(record.commitmentDigestHex, 'hex');
    const sigBuf = Buffer.from(record.validatorSignatureHex || '', 'hex');

    const payloadLen =
      2 + tenantBuf.length +
      2 + dbBuf.length +
      4 + // epoch
      8 + // commitSeq
      32 + // digest
      8 + // lockedAtUs
      2 + sigBuf.length;

    const buf = Buffer.alloc(4 + 4 + payloadLen + 32);
    let offset = 0;

    buf.write('WDBL', offset, 4, 'utf8');
    offset += 4;

    buf.writeUInt32BE(payloadLen, offset);
    offset += 4;

    const payloadStart = offset;

    buf.writeUInt16BE(tenantBuf.length, offset);
    offset += 2;
    tenantBuf.copy(buf, offset);
    offset += tenantBuf.length;

    buf.writeUInt16BE(dbBuf.length, offset);
    offset += 2;
    dbBuf.copy(buf, offset);
    offset += dbBuf.length;

    buf.writeUInt32BE(record.epoch, offset);
    offset += 4;

    buf.writeBigInt64BE(record.commitSeq, offset);
    offset += 8;

    digestBuf.copy(buf, offset);
    offset += 32;

    buf.writeBigInt64BE(record.lockedAtUs, offset);
    offset += 8;

    buf.writeUInt16BE(sigBuf.length, offset);
    offset += 2;
    sigBuf.copy(buf, offset);
    offset += sigBuf.length;

    const payloadSlice = buf.subarray(payloadStart, offset);
    const checksum = crypto.createHash('sha256').update(payloadSlice).digest();
    checksum.copy(buf, offset);

    return buf;
  }

  private readAllFromDisk(): SequenceLockRecord[] {
    if (!this.filePath || !fs.existsSync(this.filePath)) return [];

    const fileBuf = fs.readFileSync(this.filePath);
    if (fileBuf.length < 32) return [];

    const magic = fileBuf.subarray(0, 15).toString('utf8');
    if (!magic.startsWith('WDB:VAL_JRNL')) {
      throw new WolverineError(
        WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
        'Invalid validator journal file magic header'
      );
    }

    const records: SequenceLockRecord[] = [];
    let offset = 32;

    while (offset < fileBuf.length) {
      if (offset + 8 > fileBuf.length) break;

      const tag = fileBuf.subarray(offset, offset + 4).toString('utf8');
      if (tag !== 'WDBL') break;
      offset += 4;

      const payloadLen = fileBuf.readUInt32BE(offset);
      offset += 4;

      if (offset + payloadLen + 32 > fileBuf.length) break;

      const payloadBuf = fileBuf.subarray(offset, offset + payloadLen);
      const storedChecksum = fileBuf.subarray(offset + payloadLen, offset + payloadLen + 32);
      const computedChecksum = crypto.createHash('sha256').update(payloadBuf).digest();

      if (!timingSafeEqualHashes(storedChecksum, computedChecksum)) {
        throw new WolverineError(
          WolverineErrorCode.CHECKSUM_MISMATCH,
          `Checksum mismatch in validator journal at offset ${offset}`
        );
      }

      let pOff = 0;
      const tenantLen = payloadBuf.readUInt16BE(pOff);
      pOff += 2;
      const tenantId = payloadBuf.subarray(pOff, pOff + tenantLen).toString('utf8');
      pOff += tenantLen;

      const dbLen = payloadBuf.readUInt16BE(pOff);
      pOff += 2;
      const databaseId = payloadBuf.subarray(pOff, pOff + dbLen).toString('utf8');
      pOff += dbLen;

      const epoch = payloadBuf.readUInt32BE(pOff);
      pOff += 4;

      const commitSeq = payloadBuf.readBigInt64BE(pOff);
      pOff += 8;

      const commitmentDigestHex = payloadBuf.subarray(pOff, pOff + 32).toString('hex');
      pOff += 32;

      const lockedAtUs = payloadBuf.readBigInt64BE(pOff);
      pOff += 8;

      const sigLen = payloadBuf.readUInt16BE(pOff);
      pOff += 2;
      const validatorSignatureHex = sigLen > 0 ? payloadBuf.subarray(pOff, pOff + sigLen).toString('hex') : undefined;

      records.push({
        tenantId,
        databaseId,
        epoch,
        commitSeq,
        commitmentDigestHex,
        lockedAtUs,
        validatorSignatureHex,
      });

      offset += payloadLen + 32;
    }

    return records;
  }
}
