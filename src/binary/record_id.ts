import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { compareCanonicalStrings } from '../crypto/canonical.js';

export interface PrimaryKeyField {
  name: string;
  typeTag: number; // 01 BOOL, 02 U64, 03 I64, 04 UUID, 05 UTF8, 06 BYTES, 09 DECIMAL, 10 TIMESTAMP_US
  valueBuffer: Buffer;
}

/**
 * Encodes a list of primary key fields into a Canonical Primary Key Tuple binary Buffer.
 * Sorts fields deterministically by column name UTF-8 byte order ascending.
 */
export function encodePrimaryKeyTuple(fields: PrimaryKeyField[]): Buffer {
  if (!fields || fields.length === 0) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
      'Primary key tuple must contain at least one field'
    );
  }

  // Sort fields deterministically by UTF-8 byte comparison (locale-independent)
  const sortedFields = [...fields].sort((f1, f2) => compareCanonicalStrings(f1.name, f2.name));

  const buffers: Buffer[] = [];

  const countBuf = Buffer.alloc(2);
  countBuf.writeUInt16BE(sortedFields.length, 0);
  buffers.push(countBuf);

  for (const field of sortedFields) {
    const nameBuf = Buffer.from(field.name, 'utf8');
    const nameLenBuf = Buffer.alloc(2);
    nameLenBuf.writeUInt16BE(nameBuf.length, 0);

    const typeBuf = Buffer.from([field.typeTag]);

    const valLenBuf = Buffer.alloc(4);
    valLenBuf.writeUInt32BE(field.valueBuffer.length, 0);

    buffers.push(nameLenBuf, nameBuf, typeBuf, valLenBuf, field.valueBuffer);
  }

  return Buffer.concat(buffers);
}

/**
 * Decodes a Canonical Primary Key Tuple binary Buffer into primary key fields.
 * Validates ascending sorted order and non-empty name.
 */
export function decodePrimaryKeyTuple(buf: Buffer): PrimaryKeyField[] {
  if (!buf || buf.length < 2) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
      'Buffer is too short to contain primary key tuple header'
    );
  }

  let offset = 0;
  const count = buf.readUInt16BE(offset);
  offset += 2;

  if (count === 0) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
      'Primary key tuple field count must be greater than zero'
    );
  }

  const fields: PrimaryKeyField[] = [];
  let prevName: string | null = null;

  for (let i = 0; i < count; i++) {
    if (offset + 2 > buf.length) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
        'Unexpected EOF reading column name length'
      );
    }
    const nameLen = buf.readUInt16BE(offset);
    offset += 2;

    if (nameLen === 0) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
        'Column name length cannot be zero'
      );
    }

    if (offset + nameLen > buf.length) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
        'Unexpected EOF reading column name'
      );
    }
    const name = buf.toString('utf8', offset, offset + nameLen);
    offset += nameLen;

    // Enforce ascending lexicographical sort order without duplicate names
    if (prevName !== null) {
      const cmp = compareCanonicalStrings(name, prevName);
      if (cmp <= 0) {
        throw new WolverineError(
          WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
          `Primary key columns not strictly sorted or duplicate column found: "${name}" following "${prevName}"`
        );
      }
    }
    prevName = name;

    if (offset + 1 > buf.length) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
        'Unexpected EOF reading type tag'
      );
    }
    const typeTag = buf.readUInt8(offset);
    offset += 1;

    if (offset + 4 > buf.length) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
        'Unexpected EOF reading value length'
      );
    }
    const valLen = buf.readUInt32BE(offset);
    offset += 4;

    if (offset + valLen > buf.length) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
        'Unexpected EOF reading value payload'
      );
    }
    const valueBuffer = Buffer.from(buf.subarray(offset, offset + valLen));
    offset += valLen;

    fields.push({ name, typeTag, valueBuffer });
  }

  if (offset !== buf.length) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
      `Trailing bytes found in primary key tuple: ${buf.length - offset} bytes remaining`
    );
  }

  return fields;
}
