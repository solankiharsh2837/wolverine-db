import { EventEmitter } from 'node:events';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { PgLogicalClient } from './pg_logical_client.js';

export interface XLogDataHeader {
  startLsnBig: bigint;
  endLsnBig: bigint;
  sendTimeUs: bigint;
  payload: Buffer;
}

export interface PrimaryKeepaliveHeader {
  endLsnBig: bigint;
  sendTimeUs: bigint;
  replyRequested: boolean;
}

export interface StandbyStatusUpdate {
  writeLsnBig: bigint;
  flushedLsnBig: bigint;
  appliedLsnBig: bigint;
  sendTimeUs: bigint;
  replyRequested: boolean;
}

export class PgReplicationStream {
  /**
   * Encodes a Standby Status Update message ('r') for PostgreSQL replication feedback.
   */
  public static encodeStandbyStatusUpdate(status: StandbyStatusUpdate): Buffer {
    const buf = Buffer.alloc(34);
    buf.write('r', 0, 1, 'utf8');
    buf.writeBigUInt64BE(status.writeLsnBig, 1);
    buf.writeBigUInt64BE(status.flushedLsnBig, 9);
    buf.writeBigUInt64BE(status.appliedLsnBig, 17);
    buf.writeBigInt64BE(status.sendTimeUs, 25);
    buf.writeUInt8(status.replyRequested ? 1 : 0, 33);
    return buf;
  }

  /**
   * Decodes an incoming CopyData replication buffer from PostgreSQL (XLogData 'w' or PrimaryKeepalive 'k').
   */
  public static decodeCopyDataMessage(buffer: Buffer):
    | { type: 'XLogData'; header: XLogDataHeader }
    | { type: 'PrimaryKeepalive'; header: PrimaryKeepaliveHeader } {
    if (buffer.length < 1) {
      throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, 'Empty CopyData buffer');
    }

    const typeCode = String.fromCharCode(buffer[0]!);

    if (typeCode === 'w') {
      // XLogData
      if (buffer.length < 25) {
        throw new WolverineError(
          WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
          `XLogData header too short: ${buffer.length} bytes (expected >= 25)`
        );
      }

      const startLsnBig = buffer.readBigUInt64BE(1);
      const endLsnBig = buffer.readBigUInt64BE(9);
      const sendTimeUs = buffer.readBigInt64BE(17);
      const payload = Buffer.from(buffer.subarray(25));

      return {
        type: 'XLogData',
        header: {
          startLsnBig,
          endLsnBig,
          sendTimeUs,
          payload,
        },
      };
    } else if (typeCode === 'k') {
      // PrimaryKeepalive
      if (buffer.length < 18) {
        throw new WolverineError(
          WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
          `PrimaryKeepalive header too short: ${buffer.length} bytes (expected >= 18)`
        );
      }

      const endLsnBig = buffer.readBigUInt64BE(1);
      const sendTimeUs = buffer.readBigInt64BE(9);
      const replyRequested = buffer[17] === 1;

      return {
        type: 'PrimaryKeepalive',
        header: {
          endLsnBig,
          sendTimeUs,
          replyRequested,
        },
      };
    } else {
      throw new WolverineError(
        WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
        `Unknown replication CopyData message type: '${typeCode}'`
      );
    }
  }

  /**
   * Helper to construct a synthetic XLogData frame for testing.
   */
  public static createXLogDataFrame(
    startLsnBig: bigint,
    endLsnBig: bigint,
    sendTimeUs: bigint,
    pgOutputPayload: Buffer
  ): Buffer {
    const header = Buffer.alloc(25);
    header.write('w', 0, 1, 'utf8');
    header.writeBigUInt64BE(startLsnBig, 1);
    header.writeBigUInt64BE(endLsnBig, 9);
    header.writeBigInt64BE(sendTimeUs, 17);
    return Buffer.concat([header, pgOutputPayload]);
  }

  /**
   * Helper to construct a synthetic PrimaryKeepalive frame for testing.
   */
  public static createKeepaliveFrame(endLsnBig: bigint, sendTimeUs: bigint, replyRequested: boolean = false): Buffer {
    const buf = Buffer.alloc(18);
    buf.write('k', 0, 1, 'utf8');
    buf.writeBigUInt64BE(endLsnBig, 1);
    buf.writeBigInt64BE(sendTimeUs, 9);
    buf.writeUInt8(replyRequested ? 1 : 0, 17);
    return buf;
  }
}
