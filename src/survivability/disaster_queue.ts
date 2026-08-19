import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { canonicalizeJson } from '../binary/c14n.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export enum DisasterType {
  D001_REPLICATION_SLOT_LOSS = 'D001_REPLICATION_SLOT_LOSS',
  D002_LSN_DISCONTINUITY = 'D002_LSN_DISCONTINUITY',
  D003_VALIDATOR_SET_UNAVAILABLE = 'D003_VALIDATOR_SET_UNAVAILABLE',
  D004_QUORUM_UNAVAILABLE = 'D004_QUORUM_UNAVAILABLE',
  D005_JOURNAL_CORRUPTION = 'D005_JOURNAL_CORRUPTION',
  D006_EPOCH_TRANSITION_REQUIRED = 'D006_EPOCH_TRANSITION_REQUIRED',
  D007_EQUIVOCATION_DETECTED = 'D007_EQUIVOCATION_DETECTED',
  D008_TRUST_HISTORY_GAP = 'D008_TRUST_HISTORY_GAP',
}

export enum DisasterState {
  DETECTED = 'DETECTED',
  PERSISTED = 'PERSISTED',
  QUARANTINED = 'QUARANTINED',
  RECOVERY_REQUIRED = 'RECOVERY_REQUIRED',
  RECOVERY_VERIFIED = 'RECOVERY_VERIFIED',
  RESOLVED = 'RESOLVED',
}

export interface DisasterRecord {
  disasterId: string;
  disasterType: DisasterType;
  state: DisasterState;
  details: string;
  detectedAtUs: bigint;
  resolvedAtUs?: bigint;
  metadata?: Record<string, any>;
  recordChecksumHex?: string;
}

export class DurableDisasterQueue {
  private filePath?: string;
  private fd?: number;
  private disasters = new Map<string, DisasterRecord>();

  constructor(filePath?: string) {
    this.filePath = filePath;

    if (this.filePath) {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      const fileExisted = fs.existsSync(this.filePath) && fs.statSync(this.filePath).size >= 32;

      if (!fileExisted) {
        const header = Buffer.alloc(32);
        header.write('WDB:DISASTERS:v1\0', 0, 17, 'utf8');
        header.writeUInt32BE(1, 20);
        header.writeBigInt64BE(BigInt(Date.now()) * 1000n, 24);
        fs.writeFileSync(this.filePath, header);
        this.fd = fs.openSync(this.filePath, 'a+');
      } else {
        this.replayFromDisk();
        this.fd = fs.openSync(this.filePath, 'a+');
      }
    }
  }

  public recordDisaster(
    disasterType: DisasterType,
    details: string,
    metadata?: Record<string, any>
  ): DisasterRecord {
    const disasterId = `dst-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
    const detectedAtUs = BigInt(Date.now()) * 1000n;

    const record: DisasterRecord = {
      disasterId,
      disasterType,
      state: DisasterState.QUARANTINED, // Immediately enters quarantine
      details,
      detectedAtUs,
      metadata: metadata || {},
    };

    this.disasters.set(disasterId, record);
    this.persistToDisk(record);

    return { ...record };
  }

  public transitionState(
    disasterId: string,
    newState: DisasterState,
    resolutionNotes?: string
  ): DisasterRecord {
    const record = this.disasters.get(disasterId);
    if (!record) {
      throw new WolverineError(
        WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
        `Disaster record ${disasterId} not found in queue`
      );
    }

    record.state = newState;
    if (resolutionNotes) {
      record.details += ` | [TRANSITION to ${newState}]: ${resolutionNotes}`;
    }
    if (newState === DisasterState.RESOLVED) {
      record.resolvedAtUs = BigInt(Date.now()) * 1000n;
    }

    this.persistToDisk(record);
    return { ...record };
  }

  public getDisaster(disasterId: string): DisasterRecord | undefined {
    const r = this.disasters.get(disasterId);
    return r ? { ...r } : undefined;
  }

  public getActiveDisasters(): DisasterRecord[] {
    return Array.from(this.disasters.values()).filter(
      (d) => d.state !== DisasterState.RESOLVED
    );
  }

  public getAllDisasters(): DisasterRecord[] {
    return Array.from(this.disasters.values()).map((d) => ({ ...d }));
  }

  public async close(): Promise<void> {
    if (this.fd !== undefined) {
      fs.closeSync(this.fd);
      this.fd = undefined;
    }
  }

  private persistToDisk(record: DisasterRecord): void {
    if (this.fd === undefined) return;

    const payload = {
      disasterId: record.disasterId,
      disasterType: record.disasterType,
      state: record.state,
      details: record.details,
      detectedAtUs: record.detectedAtUs.toString(),
      resolvedAtUs: record.resolvedAtUs ? record.resolvedAtUs.toString() : null,
      metadata: record.metadata || {},
    };

    const jsonStr = canonicalizeJson(payload);
    const payloadBuf = Buffer.from(jsonStr, 'utf8');
    const checksum = crypto.createHash('sha256').update(payloadBuf).digest();

    const buf = Buffer.alloc(4 + 4 + payloadBuf.length + 32);
    let offset = 0;

    buf.write('WDBD', offset, 4, 'utf8');
    offset += 4;

    buf.writeUInt32BE(payloadBuf.length, offset);
    offset += 4;

    payloadBuf.copy(buf, offset);
    offset += payloadBuf.length;

    checksum.copy(buf, offset);

    fs.writeSync(this.fd, buf);
    fs.fsyncSync(this.fd);
  }

  private replayFromDisk(): void {
    if (!this.filePath || !fs.existsSync(this.filePath)) return;

    const fileBuf = fs.readFileSync(this.filePath);
    if (fileBuf.length < 32) return;

    let offset = 32;
    while (offset < fileBuf.length) {
      if (offset + 8 > fileBuf.length) break;

      const tag = fileBuf.subarray(offset, offset + 4).toString('utf8');
      if (tag !== 'WDBD') break;
      offset += 4;

      const payloadLen = fileBuf.readUInt32BE(offset);
      offset += 4;

      if (offset + payloadLen + 32 > fileBuf.length) break;

      const payloadBuf = fileBuf.subarray(offset, offset + payloadLen);
      const storedChecksum = fileBuf.subarray(offset + payloadLen, offset + payloadLen + 32);
      const computedChecksum = crypto.createHash('sha256').update(payloadBuf).digest();

      if (storedChecksum.equals(computedChecksum)) {
        try {
          const raw = JSON.parse(payloadBuf.toString('utf8'));
          const rec: DisasterRecord = {
            disasterId: raw.disasterId,
            disasterType: raw.disasterType as DisasterType,
            state: raw.state as DisasterState,
            details: raw.details,
            detectedAtUs: BigInt(raw.detectedAtUs),
            resolvedAtUs: raw.resolvedAtUs ? BigInt(raw.resolvedAtUs) : undefined,
            metadata: raw.metadata || {},
          };
          // Updates/transitions overwrite earlier state in the map
          this.disasters.set(rec.disasterId, rec);
        } catch {
          // Skip malformed record
        }
      }

      offset += payloadLen + 32;
    }
  }
}
