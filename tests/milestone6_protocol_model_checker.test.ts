import { describe, it, expect } from 'vitest';
import { ProtocolModelChecker } from '../src/index.js';

describe('Milestone 6.6 — Formal Protocol Model Checker Laboratory', () => {
  it('1. Verifies Wolverine Byzantine Safety Theorem on N=5, M=4, f=1: Zero counterexamples across 1,024 configurations', () => {
    const result = ProtocolModelChecker.verifySafetyTheorem({
      totalValidators: 5,
      quorumThreshold: 4,
      maxByzantineFaults: 1,
    });

    expect(result.safetyInvariantHolds).toBe(true);
    expect(result.conflictingFinalityCounterexamples).toBe(0);
    expect(result.exploredConfigurations).toBe(1024);
    expect(result.proofSummary).toContain('FORMAL VERIFICATION PASSED');
  });

  it('2. Detects Insecure Quorum Configuration: Model checker flags conflicting finality when M is below Byzantine safety minimum', () => {
    // If someone sets M=3 for N=5 with f=1 Byzantine node, conflicting finality IS possible!
    const result = ProtocolModelChecker.verifySafetyTheorem({
      totalValidators: 5,
      quorumThreshold: 3, // Insecure threshold!
      maxByzantineFaults: 1,
    });

    expect(result.safetyInvariantHolds).toBe(false);
    expect(result.conflictingFinalityCounterexamples).toBeGreaterThan(0);
    expect(result.proofSummary).toContain('SAFETY VIOLATION');
  });
});
