import { describe, it, expect } from 'vitest';
import { WolverineTrustService, WolverineLegacyEvidenceAgent } from '../../src/index.js';

describe('Wolverine Trust Service Interface (WDB-0076)', () => {
  it('property: anchors and verifies tenant-isolated checkpoint commitments in trust ledger', async () => {
    const trustService = new WolverineTrustService();
    const evidenceAgent = new WolverineLegacyEvidenceAgent(
      trustService,
      'tenant-enterprise-01',
      'db-primary-ledger'
    );

    const checkpointId = '00000000-0000-0000-0000-000000001842';
    const checkpointDigest = Buffer.alloc(32, 0xaa);
    const commitSeq = 42n;

    // Agent anchors checkpoint
    const record = await evidenceAgent.forwardCheckpointCommitment(
      checkpointId,
      checkpointDigest,
      commitSeq
    );

    expect(record.commitmentId).toContain('wts-');
    expect(record.tenantId).toBe('tenant-enterprise-01');
    expect(record.checkpointId).toBe(checkpointId);
    expect(record.ledgerProof).toBeDefined();

    // Verify valid digest
    const isValid = await evidenceAgent.verifyCheckpointWithTrustLedger(checkpointId, checkpointDigest);
    expect(isValid).toBe(true);

    // Verify invalid digest
    const isInvalid = await evidenceAgent.verifyCheckpointWithTrustLedger(
      checkpointId,
      Buffer.alloc(32, 0xbb)
    );
    expect(isInvalid).toBe(false);
  });
});
