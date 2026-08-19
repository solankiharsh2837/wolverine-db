import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  BatchAnchorManager,
  CanonicalQuorumCertificate,
  CanonicalAnchorBatch,
  computeAnchorBatchDigest,
} from '../src/index.js';

describe('Milestone 5.1, 5.2 & 5.4 — Plane 3 Canonical Batch Anchoring & Monotonicity', () => {
  function makeMockQC(seq: bigint): CanonicalQuorumCertificate {
    const rawPayload = `qc_payload_${seq}`;
    const certDigest = crypto.createHash('sha256').update(rawPayload).digest('hex');
    const cmtDigest = crypto.createHash('sha256').update(`cmt_${seq}`).digest('hex');

    return {
      certificateVersion: 2,
      validatorSetId: 'valset-prod-01',
      epoch: 1,
      commitSeq: seq,
      commitmentDigestHex: cmtDigest,
      finalizedAtUs: 1723800000000000n + seq * 1000n,
      quorumCount: 5,
      attestations: [],
      certificateDigestHex: certDigest,
    };
  }

  it('1. Monotonic Batch Anchoring: batches 20 QCs into 2 continuous hash-chained Anchor Batches', () => {
    const manager = new BatchAnchorManager('base-mainnet', 'valset-prod-01', 1, 10);

    const batches: CanonicalAnchorBatch[] = [];

    // Enqueue 20 QCs
    for (let seq = 1n; seq <= 20n; seq++) {
      const qc = makeMockQC(seq);
      const batch = manager.enqueueQuorumCertificate(qc);
      if (batch) {
        batches.push(batch);
      }
    }

    expect(batches.length).toBe(2);

    // Batch 1 assertions
    const b1 = batches[0]!;
    expect(b1.startLedgerSeq).toBe(1n);
    expect(b1.endLedgerSeq).toBe(10n);
    expect(b1.previousAnchorRootHex).toBe('00'.repeat(32));
    expect(b1.networkId).toBe('base-mainnet');

    // Batch 2 assertions (continuity with Batch 1)
    const b2 = batches[1]!;
    expect(b2.startLedgerSeq).toBe(11n);
    expect(b2.endLedgerSeq).toBe(20n);
    expect(b2.previousAnchorRootHex).toBe(b1.anchorBatchDigestHex);

    // Verify deterministic digest derivation
    const recomputedB2Digest = computeAnchorBatchDigest(b2);
    expect(b2.anchorBatchDigestHex).toBe(recomputedB2Digest.toString('hex'));
  });

  it('2. Sequence Discontinuity Defense: non-contiguous start sequence in subsequent batch is rejected', () => {
    const manager = new BatchAnchorManager('base-mainnet', 'valset-prod-01', 1, 5);

    // Batch 1 (seq 1..5)
    for (let seq = 1n; seq <= 5n; seq++) {
      manager.enqueueQuorumCertificate(makeMockQC(seq));
    }

    // Try to enqueue seq 8 (gap: missing 6, 7)
    expect(() => {
      manager.enqueueQuorumCertificate(makeMockQC(8n));
      manager.flushBatch();
    }).toThrowError(/Anchor batch sequence discontinuity: expected startSeq 6, observed 8/);
  });
});
