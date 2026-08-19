import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { MAGIC_HEADER, TaggedField } from './encoder.js';

export interface DecodedBinaryRecord {
  recordType: number;
  flags: number;
  fields: TaggedField[];
  getFieldByTag(tag: number): TaggedField | undefined;
}

export function decodeBinaryRecord(buf: Buffer): DecodedBinaryRecord {
  if (buf.length < 9) {
    throw new WolverineError(
      WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
      'Buffer length too short for binary record header'
    );
  }

  // Validate magic header
  if (!buf.subarray(0, 4).equals(MAGIC_HEADER)) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_MAGIC_HEADER,
      `Invalid magic header bytes: 0x${buf.subarray(0, 4).toString('hex')}`
    );
  }

  const recordType = buf.readUInt8(4);
  if (recordType < 1 || recordType > 6) {
    throw new WolverineError(
      WolverineErrorCode.UNKNOWN_RECORD_TYPE,
      `Unknown record type: ${recordType}`
    );
  }

  const flags = buf.readUInt16BE(5);
  const fieldCount = buf.readUInt16BE(7);

  let offset = 9;
  const fields: TaggedField[] = [];
  let prevTag = -1;

  for (let i = 0; i < fieldCount; i++) {
    if (offset + 7 > buf.length) {
      throw new WolverineError(
        WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
        `Unexpected end of buffer reading field header at index ${i}`
      );
    }

    const tag = buf.readUInt16BE(offset);
    offset += 2;

    if (tag <= prevTag) {
      if (tag === prevTag) {
        throw new WolverineError(
          WolverineErrorCode.DUPLICATE_FIELD_TAG,
          `Duplicate field tag ${tag} found at index ${i}`
        );
      }
      throw new WolverineError(
        WolverineErrorCode.UNSORTED_FIELD_TAGS,
        `Unsorted field tag ${tag} follows ${prevTag}`
      );
    }
    prevTag = tag;

    const typeTag = buf.readUInt8(offset);
    offset += 1;

    const length = buf.readUInt32BE(offset);
    offset += 4;

    if (offset + length > buf.length) {
      throw new WolverineError(
        WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
        `Field tag ${tag} payload extends past end of buffer`
      );
    }

    const payload = Buffer.from(buf.subarray(offset, offset + length));
    offset += length;

    fields.push({ tag, typeTag, payload });
  }

  if (offset !== buf.length) {
    throw new WolverineError(
      WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
      `Trailing bytes found in binary record: expected length ${offset}, got ${buf.length}`
    );
  }

  return {
    recordType,
    flags,
    fields,
    getFieldByTag(tag: number) {
      return fields.find((f) => f.tag === tag);
    },
  };
}
