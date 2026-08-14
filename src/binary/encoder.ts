import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export const MAGIC_HEADER = Buffer.from([0x57, 0x44, 0x42, 0x01]); // WDB\x01

export interface TaggedField {
  tag: number; // u16be
  typeTag: number; // u8
  payload: Buffer;
}

/**
 * Encodes header and tagged fields into a canonical binary buffer.
 * Enforces tag uniqueness and strictly ascending tag order.
 */
export function encodeBinaryRecord(
  recordType: number,
  fields: TaggedField[],
  flags = 0
): Buffer {
  if (recordType < 1 || recordType > 6) {
    throw new WolverineError(
      WolverineErrorCode.UNKNOWN_RECORD_TYPE,
      `Unknown record type: ${recordType}`
    );
  }

  // Validate tag ordering and uniqueness
  let prevTag = -1;
  for (let i = 0; i < fields.length; i++) {
    const field = fields[i];
    if (field.tag <= prevTag) {
      if (field.tag === prevTag) {
        throw new WolverineError(
          WolverineErrorCode.DUPLICATE_FIELD_TAG,
          `Duplicate field tag ${field.tag} at index ${i}`
        );
      }
      throw new WolverineError(
        WolverineErrorCode.UNSORTED_FIELD_TAGS,
        `Unsorted field tag ${field.tag} follows ${prevTag}`
      );
    }
    prevTag = field.tag;
  }

  const header = Buffer.alloc(9);
  MAGIC_HEADER.copy(header, 0);
  header.writeUInt8(recordType, 4);
  header.writeUInt16BE(flags, 5);
  header.writeUInt16BE(fields.length, 7);

  const fieldBuffers: Buffer[] = [header];

  for (const field of fields) {
    const tagBuf = Buffer.alloc(2);
    tagBuf.writeUInt16BE(field.tag, 0);

    const typeBuf = Buffer.from([field.typeTag]);

    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(field.payload.length, 0);

    fieldBuffers.push(tagBuf, typeBuf, lenBuf, field.payload);
  }

  return Buffer.concat(fieldBuffers);
}
