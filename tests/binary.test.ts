import { describe, it, expect } from 'vitest';
import { encodeBinaryRecord } from '../src/binary/encoder.js';
import { decodeBinaryRecord } from '../src/binary/decoder.js';
import { validateAndNormalizeDecimal } from '../src/binary/decimal.js';
import { encodePrimaryKeyTuple, decodePrimaryKeyTuple } from '../src/binary/record_id.js';
import { WolverineErrorCode } from '../src/errors/codes.js';

describe('Binary Format & Encoder/Decoder (WDB-0002)', () => {
  it('encodes and decodes valid binary record', () => {
    const f1 = { tag: 1, typeTag: 2, payload: Buffer.from('0000000000000001', 'hex') };
    const f2 = { tag: 2, typeTag: 5, payload: Buffer.from('test', 'utf8') };

    const encoded = encodeBinaryRecord(1, [f1, f2]);
    const decoded = decodeBinaryRecord(encoded);

    expect(decoded.recordType).toBe(1);
    expect(decoded.fields.length).toBe(2);
    expect(decoded.getFieldByTag(1)?.payload.toString('hex')).toBe('0000000000000001');
    expect(decoded.getFieldByTag(2)?.payload.toString('utf8')).toBe('test');
  });

  it('rejects unsorted field tags', () => {
    const f1 = { tag: 5, typeTag: 2, payload: Buffer.from([1]) };
    const f2 = { tag: 2, typeTag: 2, payload: Buffer.from([2]) };

    expect(() => encodeBinaryRecord(1, [f1, f2])).toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.UNSORTED_FIELD_TAGS })
    );
  });

  it('rejects duplicate field tags', () => {
    const f1 = { tag: 3, typeTag: 2, payload: Buffer.from([1]) };
    const f2 = { tag: 3, typeTag: 2, payload: Buffer.from([2]) };

    expect(() => encodeBinaryRecord(1, [f1, f2])).toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.DUPLICATE_FIELD_TAG })
    );
  });

  it('validates decimal strict grammar and rejects scientific/leading zeros/negative zeros', () => {
    expect(validateAndNormalizeDecimal('123.45')).toBe('123.45');
    expect(validateAndNormalizeDecimal('0')).toBe('0');
    expect(validateAndNormalizeDecimal('-12.3')).toBe('-12.3');

    // Negative tests
    expect(() => validateAndNormalizeDecimal('1e5')).toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.INVALID_DECIMAL_FORMAT })
    );
    expect(() => validateAndNormalizeDecimal('012')).toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.INVALID_DECIMAL_FORMAT })
    );
    expect(() => validateAndNormalizeDecimal('-0')).toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.INVALID_DECIMAL_FORMAT })
    );
    expect(() => validateAndNormalizeDecimal('-0.0')).toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.INVALID_DECIMAL_FORMAT })
    );
  });

  it('encodes and decodes primary key tuples with column name sorting', () => {
    const val1 = Buffer.alloc(8); val1.writeBigUInt64BE(100n);
    const val2 = Buffer.from('tenant_a', 'utf8');

    const tuple = encodePrimaryKeyTuple([
      { name: 'tenant_id', typeTag: 5, valueBuffer: val2 },
      { name: 'account_id', typeTag: 2, valueBuffer: val1 },
    ]);

    const decoded = decodePrimaryKeyTuple(tuple);
    expect(decoded.length).toBe(2);
    expect(decoded[0].name).toBe('account_id');
    expect(decoded[1].name).toBe('tenant_id');
  });
});
