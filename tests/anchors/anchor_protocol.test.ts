import { describe, it, expect } from 'vitest';
import { computeAnchorCommitmentDigest } from '../../src/anchors/protocol.js';
import { AnchorDomainType } from '../../src/anchors/types.js';

describe('Anchor Protocol (WDB-0020 Hardening)', () => {
  it('computes canonical anchor commitment digest with domain separation and chain binding', () => {
    const checkpointDigest = Buffer.alloc(32, 0x5a);
    const checkpointId = '00000000-0000-0000-0000-000000000042';
    const chainId = '1'; // Ethereum Mainnet
    const commitSeq = 42n;
    const timestampUs = 1723500000000000n;

    const digest1 = computeAnchorCommitmentDigest({
      domainType: AnchorDomainType.EVM,
      chainId,
      checkpointId,
      checkpointDigest,
      commitSeq,
      timestampUs,
    });

    expect(digest1).toHaveLength(32);

    // Differing chainId must produce differing digest (EIP-155 domain separation)
    const digest2 = computeAnchorCommitmentDigest({
      domainType: AnchorDomainType.EVM,
      chainId: '8453', // Base
      checkpointId,
      checkpointDigest,
      commitSeq,
      timestampUs,
    });

    expect(digest1.equals(digest2)).toBe(false);
  });
});
