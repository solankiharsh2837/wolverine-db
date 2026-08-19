import { describe, it, expect } from 'vitest';
import { CanonicalCryptoFuzzer } from '../src/index.js';

describe('Milestone 6.1 — Cryptographic Correctness & Canonical Fuzzing Laboratory', () => {
  it('1. Key Permutation Invariance: JSON key order changes produce identical RFC 8785 canonical bytes', () => {
    const res = CanonicalCryptoFuzzer.testKeyPermutationInvariance();
    expect(res.passed).toBe(true);
  });

  it('2. Zero Normalization: -0 is canonically normalized to 0', () => {
    const res = CanonicalCryptoFuzzer.testZeroNormalization();
    expect(res.passed).toBe(true);
  });

  it('3. Collision Resistance: 1,000 distinct randomized inputs produce 1,000 distinct SHA-256 digests', () => {
    const res = CanonicalCryptoFuzzer.testCollisionResistance(1000);
    expect(res.passed).toBe(true);
  });

  it('4. Domain Separation Integrity: Commitment, Quorum Certificate, and Validator Attestation domains are disjoint', () => {
    const res = CanonicalCryptoFuzzer.testDomainSeparationIntegrity();
    expect(res.passed).toBe(true);
  });
});
