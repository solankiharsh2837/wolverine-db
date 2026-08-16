import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export enum CanonicalFieldType {
  STRING = 0x01,
  BUFFER = 0x02,
  INT32 = 0x03,
  BIGINT64 = 0x04,
  BOOLEAN = 0x05,
}

export type CanonicalFieldInput = string | Buffer | number | bigint | boolean;

/**
 * Compares two strings using raw UTF-8 byte comparison for locale-independent determinism.
 */
export function compareCanonicalStrings(s1: string, s2: string): number {
  const b1 = Buffer.from(s1, 'utf8');
  const b2 = Buffer.from(s2, 'utf8');
  return Buffer.compare(b1, b2);
}

/**
 * Encodes an array of typed fields into an unambiguous, length-prefixed canonical protocol tuple.
 * Format: DomainPrefix || Field_1 || Field_2 || ... || Field_N
 * Each field is encoded as: [TypeTag: 1 byte] || [Length: 4 bytes (if string/buffer)] || [Value]
 */
export function encodeProtocolTuple(
  domain: string,
  fields: CanonicalFieldInput[]
): Buffer {
  const parts: Buffer[] = [Buffer.from(domain, 'utf8')];

  for (const field of fields) {
    if (typeof field === 'string') {
      const strBuf = Buffer.from(field, 'utf8');
      const header = Buffer.alloc(5);
      header.writeUInt8(CanonicalFieldType.STRING, 0);
      header.writeUInt32BE(strBuf.length, 1);
      parts.push(header, strBuf);
    } else if (Buffer.isBuffer(field)) {
      const header = Buffer.alloc(5);
      header.writeUInt8(CanonicalFieldType.BUFFER, 0);
      header.writeUInt32BE(field.length, 1);
      parts.push(header, field);
    } else if (typeof field === 'number') {
      const buf = Buffer.alloc(5);
      buf.writeUInt8(CanonicalFieldType.INT32, 0);
      buf.writeInt32BE(field, 1);
      parts.push(buf);
    } else if (typeof field === 'bigint') {
      const buf = Buffer.alloc(9);
      buf.writeUInt8(CanonicalFieldType.BIGINT64, 0);
      buf.writeBigInt64BE(field, 1);
      parts.push(buf);
    } else if (typeof field === 'boolean') {
      const buf = Buffer.alloc(2);
      buf.writeUInt8(CanonicalFieldType.BOOLEAN, 0);
      buf.writeUInt8(field ? 1 : 0, 1);
      parts.push(buf);
    } else {
      throw new WolverineError(
        WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
        `Unsupported field type for canonical protocol tuple: ${typeof field}`
      );
    }
  }

  return Buffer.concat(parts);
}
