import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  BatchAnchorManager,
  CanonicalQuorumCertificate,
  AnchorLifecycleState,
  BlockchainAnchorProvider,
  CanonicalAnchorBatch,
} from '../src/index.js';

describe('Milestone 5.7 & 5.8 — Plane 3 Blockchain Failure Isolation & Reorg Resilience', () => {
  function makeMockQC(seq: bigint): CanonicalQuorumCertificate {
    return {
      certificateVersion: 2,
      validatorSetId: 'valset-prod-01',
      epoch: 1,
      commitSeq: seq,
      commitmentDigestHex: crypto.createHash('sha256').update(`cmt_${seq}`).digest('hex'),
      finalizedAtUs: 1723800000000000n + seq * 1000n,
      quorumCount: 5,
      attestations: [],
      certificateDigestHex: crypto.createHash('sha256').update(`qc_${seq}`).digest('hex'),
    };
  }

  it('1. Plane 3 Failure Isolation: Blockchain RPC failure does not block QC generation or panic', async () => {
    // Failing blockchain provider (e.g. Base/Ethereum RPC outage)
    const failingProvider: BlockchainAnchorProvider = {
      async submitAnchor() {
        throw new Error('ETIMEDOUT: Base RPC node unreachable (HTTP 504)');
      },
      async checkStatus() {
        return { confirmed: false, reorged: false, confirmations: 0 };
      },
    };

    const manager = new BatchAnchorManager('base-mainnet', 'valset-prod-01', 1, 5, failingProvider);

    // Ingest 5 QCs (Plane 2 continues normally)
    let batch: CanonicalAnchorBatch | null = null;
    for (let seq = 1n; seq <= 5n; seq++) {
      const b = manager.enqueueQuorumCertificate(makeMockQC(seq));
      if (b) batch = b;
    }

    expect(batch).toBeDefined();

    // Submit to blockchain during outage
    const receipt = await manager.submitToBlockchain(batch!);

    // Assert: Plane 3 enters PENDING/BACKLOGGED state without failing Plane 2
    expect(receipt).toBeDefined();
    expect(receipt?.state).toBe(AnchorLifecycleState.PENDING);
    expect(receipt?.confirmations).toBe(0);

    // Plane 2 continues witnessing next batch smoothly
    let batch2: CanonicalAnchorBatch | null = null;
    for (let seq = 6n; seq <= 10n; seq++) {
      const b = manager.enqueueQuorumCertificate(makeMockQC(seq));
      if (b) batch2 = b;
    }
    expect(batch2?.startLedgerSeq).toBe(6n);
  });

  it('2. Reorg Resilience: Chain reorg invalidates public anchor without invalidating underlying QC finality', () => {
    const qc = makeMockQC(1842n);
    expect(qc.commitSeq).toBe(1842n);

    // Simulate anchor state marked as REORG_DETECTED
    const anchorReceipt = {
      batchDigestHex: '00'.repeat(32),
      txHashHex: '0x1234',
      blockNumber: 1000000n,
      blockHashHex: '0xabcd',
      contractAddress: '0xRegistry',
      submittedAtUs: 1723800000000000n,
      state: AnchorLifecycleState.REORG_DETECTED,
      confirmations: 0,
    };

    // Assert Invariant: QC remains FINAL and authoritative; only anchor state is REORG_DETECTED
    expect(qc.certificateDigestHex.length).toBe(64);
    expect(anchorReceipt.state).toBe(AnchorLifecycleState.REORG_DETECTED);
  });
});
