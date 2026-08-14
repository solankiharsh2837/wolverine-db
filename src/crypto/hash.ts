import crypto from 'node:crypto';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export const GENESIS_PREDECEASED_HASH = Buffer.alloc(32, 0);

export function sha256(buf: Buffer): Buffer {
  return crypto.createHash('sha256').update(buf).digest();
}

/**
 * Computes constant-time equality comparison between two 32-byte hash buffers.
 */
export function timingSafeEqualHashes(h1: Buffer, h2: Buffer): boolean {
  if (h1.length !== 32 || h2.length !== 32) {
    return false;
  }
  return crypto.timingSafeEqual(h1, h2);
}

/**
 * Computes Change Hash: SHA256("WDB:CHANGE:v1" || u32be(len) || record_bytes || previous_hash)
 */
export function computeChangeHash(
  recordBytes: Buffer,
  previousHash: Buffer
): Buffer {
  if (previousHash.length !== 32) {
    throw new WolverineError(
      WolverineErrorCode.MISSING_PREDECEASED_HASH,
      `Previous change hash must be 32 bytes, got ${previousHash.length}`
    );
  }

  const domain = Buffer.from('WDB:CHANGE:v1', 'utf8');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(recordBytes.length, 0);

  const payload = Buffer.concat([domain, lenBuf, recordBytes, previousHash]);
  return sha256(payload);
}

/**
 * Computes Version Hash: SHA256("WDB:VERSION:v1" || u32be(len) || version_bytes || parent_version_hash)
 */
export function computeVersionHash(
  versionBytes: Buffer,
  parentVersionHash: Buffer
): Buffer {
  if (parentVersionHash.length !== 32) {
    throw new WolverineError(
      WolverineErrorCode.MISSING_PREDECEASED_HASH,
      `Parent version hash must be 32 bytes, got ${parentVersionHash.length}`
    );
  }

  const domain = Buffer.from('WDB:VERSION:v1', 'utf8');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(versionBytes.length, 0);

  const payload = Buffer.concat([domain, lenBuf, versionBytes, parentVersionHash]);
  return sha256(payload);
}
