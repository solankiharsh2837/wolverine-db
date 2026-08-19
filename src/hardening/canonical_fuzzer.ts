import crypto from 'node:crypto';
import { canonicalizeJson } from '../binary/c14n.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export interface FuzzTestResult {
  passed: boolean;
  name: string;
  details: string;
}

export class CanonicalCryptoFuzzer {
  /**
   * Asserts that key permutation does not alter RFC 8785 canonical output.
   */
  public static testKeyPermutationInvariance(): FuzzTestResult {
    const objA = { z: 100, a: 'alpha', m: { b: true, a: [1, 2, 3] } };
    const objB = { a: 'alpha', m: { a: [1, 2, 3], b: true }, z: 100 };

    const c14nA = canonicalizeJson(objA);
    const c14nB = canonicalizeJson(objB);

    const match = c14nA === c14nB;
    return {
      passed: match,
      name: 'Key Permutation Invariance',
      details: match
        ? 'Identical canonical JSON across distinct key orders'
        : `Mismatch: ${c14nA} !== ${c14nB}`,
    };
  }

  /**
   * Asserts that numbers with equivalent value (-0 vs 0) normalize correctly.
   */
  public static testZeroNormalization(): FuzzTestResult {
    const zeroPos = canonicalizeJson({ val: 0 });
    const zeroNeg = canonicalizeJson({ val: -0 });

    const match = zeroPos === zeroNeg && zeroPos === '{"val":0}';
    return {
      passed: match,
      name: 'Negative Zero Normalization',
      details: match ? '-0 normalized to 0' : `Failed: ${zeroNeg} !== ${zeroPos}`,
    };
  }

  /**
   * Asserts that distinct payloads never produce the same canonical hash.
   */
  public static testCollisionResistance(iterations = 1000): FuzzTestResult {
    const seenHashes = new Set<string>();

    for (let i = 0; i < iterations; i++) {
      const payload = {
        seq: i,
        nonce: crypto.randomBytes(8).toString('hex'),
        data: `payload_${i}`,
      };
      const c14n = canonicalizeJson(payload);
      const hash = crypto.createHash('sha256').update(c14n, 'utf8').digest('hex');

      if (seenHashes.has(hash)) {
        return {
          passed: false,
          name: 'Collision Resistance',
          details: `Hash collision detected at iteration ${i}`,
        };
      }
      seenHashes.add(hash);
    }

    return {
      passed: true,
      name: 'Collision Resistance',
      details: `${iterations} unique inputs produced ${iterations} distinct hashes`,
    };
  }

  /**
   * Asserts that domain separation prefixes prevent cross-protocol digest collisions.
   */
  public static testDomainSeparationIntegrity(): FuzzTestResult {
    const rawData = Buffer.from('test_payload_123', 'utf8');

    const digestCommitment = crypto
      .createHash('sha256')
      .update(Buffer.concat([Buffer.from('WDB:COMMITMENT:v2:', 'utf8'), rawData]))
      .digest();

    const digestQuorumCert = crypto
      .createHash('sha256')
      .update(Buffer.concat([Buffer.from('WDB:QUORUM_CERT:v2:', 'utf8'), rawData]))
      .digest();

    const digestValAttest = crypto
      .createHash('sha256')
      .update(Buffer.concat([Buffer.from('WDB:VAL_ATTEST:v2:', 'utf8'), rawData]))
      .digest();

    const distinct =
      !timingSafeEqualHashes(digestCommitment, digestQuorumCert) &&
      !timingSafeEqualHashes(digestCommitment, digestValAttest) &&
      !timingSafeEqualHashes(digestQuorumCert, digestValAttest);

    return {
      passed: distinct,
      name: 'Domain Separation Integrity',
      details: distinct
        ? 'All protocol domains produce disjoint digest sets'
        : 'Domain prefix collision detected',
    };
  }
}
