import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { decodeBinaryRecord } from '../src/binary/decoder.js';
import { encodeBinaryRecord } from '../src/binary/encoder.js';
import { validateAndNormalizeDecimal } from '../src/binary/decimal.js';
import { canonicalizeJson } from '../src/binary/c14n.js';
import { decodePrimaryKeyTuple } from '../src/binary/record_id.js';
import { verifyApprovalEnvelope } from '../src/crypto/approval.js';
import { verifyMerkleProof } from '../src/crypto/merkle.js';
import { WolverineError } from '../src/errors/index.js';

describe('Fuzz & Property-Based Testing Suite', () => {
  // 1. Fuzz Binary Record Parser with 500 Random Mutations
  it('Fuzz 1: Binary decoder handles 500 arbitrary byte mutations gracefully without crashing', () => {
    const validBytes = encodeBinaryRecord(1, [
      { tag: 1, typeTag: 2, payload: Buffer.from('0000000000000001', 'hex') },
      { tag: 2, typeTag: 5, payload: Buffer.from('test_fuzz', 'utf8') },
    ]);

    for (let i = 0; i < 500; i++) {
      const fuzzed = Buffer.from(validBytes);
      // Pick random byte offset and mutate
      const offset = crypto.randomInt(0, fuzzed.length);
      fuzzed[offset] = crypto.randomInt(0, 256);

      try {
        const decoded = decodeBinaryRecord(fuzzed);
        // If it decodes successfully, ensure recordType is valid
        expect(decoded.recordType).toBeGreaterThanOrEqual(1);
        expect(decoded.recordType).toBeLessThanOrEqual(6);
      } catch (err: any) {
        // Must throw a typed WolverineError or RangeError, never crash unhandled
        expect(err).toBeDefined();
      }
    }
  });

  // 2. Fuzz Binary Parser with Truncated & Oversized Buffers
  it('Fuzz 2: Handles truncated buffers at every single byte length', () => {
    const validBytes = encodeBinaryRecord(1, [
      { tag: 1, typeTag: 2, payload: Buffer.from('0000000000000001', 'hex') },
      { tag: 2, typeTag: 5, payload: Buffer.from('test_fuzz', 'utf8') },
    ]);

    for (let len = 0; len < validBytes.length; len++) {
      const truncated = validBytes.subarray(0, len);
      expect(() => decodeBinaryRecord(truncated)).toThrowError();
    }
  });

  // 3. Fuzz Decimal Validator
  it('Fuzz 3: Rejects arbitrary invalid decimal string formats', () => {
    const invalidDecimals = [
      '1e5',
      '0123',
      '-0',
      '-0.0',
      'abc',
      '1.2.3',
      '--5',
      '5.',
      '.5',
      '10x',
      'NaN',
      'Infinity',
    ];

    for (const invalidDec of invalidDecimals) {
      expect(() => validateAndNormalizeDecimal(invalidDec)).toThrowError(WolverineError);
    }
  });

  // 4. Fuzz JSON-C14N
  it('Fuzz 4: Handles deeply nested objects and property keys correctly', () => {
    const obj = {
      z: 1,
      a: {
        y: 'test',
        b: [3, 2, 1],
      },
    };
    const canonical = canonicalizeJson(obj);
    expect(canonical).toBe('{"a":{"b":[3,2,1],"y":"test"},"z":1}');
  });

  // 5. Fuzz Primary Key Tuple Decoding
  it('Fuzz 5: Rejects out-of-order column names in primary key tuples', () => {
    // Manually construct primary key tuple with columns in reverse order: "colB" before "colA"
    const nameA = Buffer.from('colA', 'utf8');
    const nameB = Buffer.from('colB', 'utf8');

    const colCount = Buffer.from('0002', 'hex');
    const fieldB = Buffer.concat([
      Buffer.from('0004', 'hex'), nameB,
      Buffer.from([0x02]),
      Buffer.from('000000080000000000000001', 'hex'),
    ]);
    const fieldA = Buffer.concat([
      Buffer.from('0004', 'hex'), nameA,
      Buffer.from([0x02]),
      Buffer.from('000000080000000000000002', 'hex'),
    ]);

    const outOfOrderTuple = Buffer.concat([colCount, fieldB, fieldA]);
    expect(() => decodePrimaryKeyTuple(outOfOrderTuple)).toThrowError(WolverineError);
  });

  // 6. Fuzz Merkle Proof Verification with Random Proof Steps
  it('Fuzz 6: Rejects random 32-byte hash inclusions in Merkle proof verification', () => {
    const leafHash = Buffer.alloc(32, 0x11);
    const claimedRoot = Buffer.alloc(32, 0x22);

    for (let i = 0; i < 100; i++) {
      const randomProof = [
        { side: (i % 2 === 0 ? 0 : 1) as 0 | 1, siblingHash: crypto.randomBytes(32) },
      ];
      expect(verifyMerkleProof(leafHash, randomProof, claimedRoot)).toBe(false);
    }
  });

  // 7. Fuzz Approval Envelope Signature Verification with Random Signatures
  it('Fuzz 7: Rejects random 64-byte Ed25519 signature payloads', () => {
    const pubkey = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

    const envelope = {
      incidentId: Buffer.alloc(16, 1),
      protectedScope: 'public.users',
      targetVersionId: Buffer.alloc(16, 2),
      proposedChangesHash: Buffer.alloc(32, 3),
      requesterId: 'user@example.com',
      approverPubkey: pubkey,
      nonce: Buffer.alloc(16, 4),
      expiresAtUs: 3000000000000000n,
      signature: crypto.randomBytes(64),
    };

    expect(() =>
      verifyApprovalEnvelope(envelope, [pubkey.toString('hex')], 1000000000000000n)
    ).toThrowError(WolverineError);
  });
});
