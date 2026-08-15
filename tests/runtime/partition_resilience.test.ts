import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  DistributedTrustCluster,
  WolverineEvidenceAgentClient,
} from '../../src/index.js';

describe('Network Partition & Validator Fault Tolerance (WDB-0090, WDB-0091)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('partition tolerance: continues finalizing with 3/5 validators, halts safely when below quorum threshold', async () => {
    const cluster = new DistributedTrustCluster({ requiredQuorum: 3, totalValidators: 5 });
    const customer = genKeys();
    cluster.gateway.registerTenant('tenant-resilience', customer.pub, 'orders-db');

    const client = new WolverineEvidenceAgentClient({
      tenantId: 'tenant-resilience',
      databaseId: 'orders-db',
      customerPubkey: customer.pub,
      customerPrivateKey: customer.priv,
      gateway: cluster.gateway,
    });

    const cp1 = {
      checkpointId: '00000000-0000-0000-0000-000000000101',
      commitSeq: 101n,
      scope: 'public.orders',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 0x01),
      changeChainHead: Buffer.alloc(32, 0x00),
      createdAtUs: 1723500000000000n,
      protocolVersion: 3,
    };

    // PARTITION 2 VALIDATORS (Node 01 and Node 02)
    cluster.simulateValidatorPartition('val-node-01', true);
    cluster.simulateValidatorPartition('val-node-02', true);

    // 3 Validators remain online -> Quorum 3/5 reached -> Finalized!
    const res1 = await client.commitCheckpoint(cp1, Buffer.alloc(32, 0xaa));
    expect(res1.isSynchronized).toBe(true);
    expect(res1.proof?.quorumCertificate.quorumCount).toBe(3);

    // PARTITION 1 MORE VALIDATOR (Node 03) -> Only 2 online
    cluster.simulateValidatorPartition('val-node-03', true);

    const cp2 = {
      checkpointId: '00000000-0000-0000-0000-000000000102',
      commitSeq: 102n,
      scope: 'public.orders',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 0x02),
      changeChainHead: Buffer.alloc(32, 0x01),
      createdAtUs: 1723500100000000n,
      protocolVersion: 3,
    };

    // Below quorum -> Client queues locally!
    const res2 = await client.commitCheckpoint(cp2, Buffer.alloc(32, 0xbb));
    expect(res2.isSynchronized).toBe(false);
    expect(client.getOfflineQueueLength()).toBe(1);

    // HEAL PARTITIONS (Bring nodes back online)
    cluster.simulateValidatorPartition('val-node-01', false);
    cluster.simulateValidatorPartition('val-node-02', false);
    cluster.simulateValidatorPartition('val-node-03', false);

    // Drain queue
    const drained = await client.flushQueue();
    expect(drained).toBe(1);
    expect(client.getOfflineQueueLength()).toBe(0);
    expect(client.getCachedProof(cp2.checkpointId)?.quorumCertificate.quorumCount).toBe(5);
  });
});
