import { describe, it, expect } from 'vitest';
import { canonicalizeJson } from '../../src/binary/c14n.js';
import { computeChangeHash } from '../../src/crypto/hash.js';
import { MutationOperation } from '../../src/protocol/types.js';

describe('Capture Equivalence (WDB-0014 Scaffolding)', () => {
  it('asserts deterministic equivalence between simulated Trigger and WAL payloads', () => {
    const rawTx = {
      id: 'e48a1234-5678-4321-9abc-def012345678',
      balance: '250.00',
      owner: 'Alice',
    };

    // Trigger normalizer path
    const triggerNormalized = {
      new: { balance: '250.00', id: rawTx.id, owner: rawTx.owner },
      old: null,
    };
    const triggerJson = canonicalizeJson(triggerNormalized);

    // WAL normalizer path
    const walNormalized = {
      new: { owner: rawTx.owner, id: rawTx.id, balance: '250.00' }, // differing key order before RFC 8785
      old: null,
    };
    const walJson = canonicalizeJson(walNormalized);

    // Canonical JSON output MUST be identical bit-for-bit
    expect(triggerJson).toBe(walJson);

    // Hash computation MUST be identical
    const recordId = Buffer.from('mock-pk-bytes');
    const prevHash = Buffer.alloc(32, 0);

    const triggerHash = computeChangeHash(
      Buffer.from(triggerJson, 'utf8'),
      prevHash
    );

    const walHash = computeChangeHash(
      Buffer.from(walJson, 'utf8'),
      prevHash
    );

    expect(triggerHash.toString('hex')).toBe(walHash.toString('hex'));
  });
});
