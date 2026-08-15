import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  DistributedTrustCluster,
  WolverineEvidenceAgentClient,
  TrustTimeManager,
  WolverineRuntimeCli,
} from '../../src/index.js';

describe('Trust Time & Dual-Timeline Verification (WDB-0094)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('temporal ordering proof: verifies that database state existed at or before specific Trust Sequence', async () => {
    const cluster = new DistributedTrustCluster({ requiredQuorum: 3, totalValidators: 5 });
    const customer = genKeys();
    cluster.gateway.registerTenant('tenant-fintech', customer.pub, 'orders-db');

    const client = new WolverineEvidenceAgentClient({
      tenantId: 'tenant-fintech',
      databaseId: 'orders-db',
      customerPubkey: customer.pub,
      customerPrivateKey: customer.priv,
      gateway: cluster.gateway,
    });

    const timeManager = new TrustTimeManager();

    const cp1 = {
      checkpointId: '00000000-0000-0000-0000-000000001842',
      commitSeq: 1842n,
      scope: 'public.orders',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 0x11),
      changeChainHead: Buffer.alloc(32, 0x00),
      createdAtUs: 1723500000000000n,
      protocolVersion: 3,
    };
    const cp2 = {
      checkpointId: '00000000-0000-0000-0000-000000001917',
      commitSeq: 1917n,
      scope: 'public.orders',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 0x22),
      changeChainHead: Buffer.alloc(32, 0x11),
      createdAtUs: 1723500100000000n,
      protocolVersion: 3,
    };

    // Commit 1842
    const res1 = await client.commitCheckpoint(cp1, Buffer.alloc(32, 0xaa));
    const record1 = timeManager.registerProof(res1.proof!);

    // Commit 1917
    const res2 = await client.commitCheckpoint(cp2, Buffer.alloc(32, 0xbb));
    const record2 = timeManager.registerProof(res2.proof!);

    expect(record1.commitSeq).toBe(1842n);
    expect(record1.ledgerSeq).toBe(1n);

    expect(record2.commitSeq).toBe(1917n);
    expect(record2.ledgerSeq).toBe(2n);

    // Verify temporal ordering: Checkpoint 1842 existed prior to ledgerSeq 1
    const check1 = timeManager.verifyTemporalOrdering('tenant-fintech', 'orders-db', 1842n, 1n);
    expect(check1.isPrecedent).toBe(true);

    // Verify temporal ordering: Checkpoint 1917 did NOT exist prior to ledgerSeq 1
    const check2 = timeManager.verifyTemporalOrdering('tenant-fintech', 'orders-db', 1917n, 1n);
    expect(check2.isPrecedent).toBe(false);

    // CLI Inspection
    const inspectOutput = WolverineRuntimeCli.executeTrustTimeInspect(record1);
    expect(inspectOutput).toContain('WOLVERINE DUAL-TIMELINE RECORD');
    expect(inspectOutput).toContain('Database Time:            CommitSeq 1842');
    expect(inspectOutput).toContain('Trust Time Sequence:      LedgerSeq 1');
  });
});
