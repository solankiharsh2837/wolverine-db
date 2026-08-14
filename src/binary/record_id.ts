import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface PrimaryKeyField {
  name: string;
  typeTag: number; // 01 BOOL, 02 U64, 03 I64, 04 UUID, 05 UTF8, 06 BYTES, 09 DECIMAL, 10 TIMESTAMP_US
  valueBuffer: Buffer;
}

/**
 * Encodes a list of primary key fields into a Canonical Primary Key Tuple binary Buffer.
 * Sorts fields by column name ascending.
 */
export function encodePrimaryKeyTuple(fields: PrimaryKeyField[]): Buffer {
  if (!fields || fields.length === 0) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
      'Primary key tuple must contain at least one field'
    );
  }

  // Sort fields lexicographically by column name ascending
  const sortedFields = [...fields].sort((f1, f2) => f1.name.localeCompare(f2.name));

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
 * Decodes a Canonical Primary Key Tuple binary Buffer.
 */
export function decodePrimaryKeyTuple(buf: Buffer): PrimaryKeyField[] {
  if (buf.length < 2) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
      'Buffer too short to contain primary key column count'
    );
  }

  let offset = 0;
  const colCount = buf.readUInt16BE(offset);
  offset += 2;

  const fields: PrimaryKeyField[] = [];
  let prevName = '';

  for (let i = 0; i < colCount; i++) {
    if (offset + 2 > buf.length) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
        'Truncated primary key column name length'
      );
    }
    const nameLen = buf.readUInt16BE(offset);
    offset += 2;

    if (offset + nameLen > buf.length) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
        'Truncated primary key column name'
      );
    }
    const colName = buf.toString('utf8', offset, offset + nameLen);
    offset += nameLen;

    if (colName <= prevName && i > 0) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
        `Primary key fields out of order: "${colName}" follows "${prevName}"`
      );
    }
    prevName = colName;

    if (offset + 1 > buf.length) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
        'Truncated primary key type tag'
      );
    }
    const typeTag = buf.readUInt8(offset);
    offset += 1;

    if (offset + 4 > buf.length) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
        'Truncated primary key value length'
      );
    }
    const valLen = buf.readUInt32BE(offset);
    offset += 4;

    if (offset + valLen > buf.length) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
        'Truncated primary key value payload'
      );
    }
    const valueBuffer = Buffer.from(buf.subarray(offset, offset + valLen));
    offset += valLen;

    fields.push({ name: colName, typeTag, valueBuffer });
  }

  return fields;
}
