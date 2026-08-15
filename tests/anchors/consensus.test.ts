import { describe, it, expect } from 'vitest';
import { MultiAnchorConsensusEngine } from '../../src/anchors/consensus.js';
import { AnchorRecord, AnchorDomainType, AnchorStatus, ConsensusPolicy } from '../../src/anchors/types.js';

describe('Multi-Anchor Consensus Engine (WDB-0023 Hardening)', () => {
  const expectedDigest = Buffer.alloc(32, 0x77);

  const makeAnchor = (id: string, chainId: string, digest: Buffer, status: AnchorStatus): AnchorRecord => ({
    anchorId: id,
    domainType: AnchorDomainType.EVM,
    chainId,
    checkpointId: 'chk-1',
    checkpointDigest: digest,
    commitSeq: 1n,
    status,
    confirmationCount: status === AnchorStatus.FINALIZED ? 64 : 1,
    requiredConfirmations: 32,
    timestampUs: 1723500000000000n,
  });

  const policy2of3: ConsensusPolicy = {
    requiredQuorum: 2,
    totalAnchors: 3,
  };

  it('property: 3/3 anchors match -> CONSENSUS_VALID', () => {
    const anchors = [
      makeAnchor('a1', '1', expectedDigest, AnchorStatus.FINALIZED),
      makeAnchor('a2', '8453', expectedDigest, AnchorStatus.FINALIZED),
      makeAnchor('a3', '42161', expectedDigest, AnchorStatus.FINALIZED),
    ];

    const report = MultiAnchorConsensusEngine.evaluateConsensus(expectedDigest, anchors, policy2of3);
    expect(report.verdict).toBe('CONSENSUS_VALID');
    expect(report.matchingCount).toBe(3);
  });

  it('property: 2/3 anchors match (1 anchor offline/tampered) -> CONSENSUS_VALID quorum achieved', () => {
    const anchors = [
      makeAnchor('a1', '1', expectedDigest, AnchorStatus.FINALIZED),
      makeAnchor('a2', '8453', expectedDigest, AnchorStatus.FINALIZED),
      makeAnchor('a3', '42161', Buffer.alloc(32, 0x00), AnchorStatus.FINALIZED), // Tampered
    ];

    const report = MultiAnchorConsensusEngine.evaluateConsensus(expectedDigest, anchors, policy2of3);
    expect(report.verdict).toBe('CONSENSUS_VALID');
    expect(report.matchingCount).toBe(2);
  });

  it('property: 1/3 anchors match -> CONSENSUS_SUSPICIOUS alert', () => {
    const anchors = [
      makeAnchor('a1', '1', expectedDigest, AnchorStatus.FINALIZED),
      makeAnchor('a2', '8453', Buffer.alloc(32, 0x11), AnchorStatus.FINALIZED),
      makeAnchor('a3', '42161', Buffer.alloc(32, 0x22), AnchorStatus.FINALIZED),
    ];

    const report = MultiAnchorConsensusEngine.evaluateConsensus(expectedDigest, anchors, policy2of3);
    expect(report.verdict).toBe('CONSENSUS_SUSPICIOUS');
    expect(report.matchingCount).toBe(1);
  });

  it('property: 0/3 anchors match -> CONSENSUS_DIVERGENCE', () => {
    const anchors = [
      makeAnchor('a1', '1', Buffer.alloc(32, 0x11), AnchorStatus.FINALIZED),
      makeAnchor('a2', '8453', Buffer.alloc(32, 0x22), AnchorStatus.FINALIZED),
      makeAnchor('a3', '42161', Buffer.alloc(32, 0x33), AnchorStatus.FINALIZED),
    ];

    const report = MultiAnchorConsensusEngine.evaluateConsensus(expectedDigest, anchors, policy2of3);
    expect(report.verdict).toBe('CONSENSUS_DIVERGENCE');
    expect(report.matchingCount).toBe(0);
  });
});
