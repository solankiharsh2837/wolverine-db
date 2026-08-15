import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WolverineTrustNetworkService,
  WolverineEvidenceAgent,
} from '../../src/index.js';

describe('Trust Network Outage Resilience & Offline Queue (WDB-0086, WDB-0088)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('outage resilience: queues commitments during network outage and drains upon reconnection', async () => {
    const service = new WolverineTrustNetworkService(3, 5);
    const customer = genKeys();

    service.registerTenant('tenant-fintech', customer.pub, 'db-core');

    const agent = new WolverineEvidenceAgent({
      tenantId: 'tenant-fintech',
      databaseId: 'db-core',
      customerPubkey: customer.pub,
      customerPrivateKey: customer.priv,
      service,
    });

    // SIMULATE CLOUD OUTAGE
    service.setNetworkOnlineStatus(false);

    const cp1 = {
      checkpointId: '00000000-0000-0000-0000-000000000101',
      commitSeq: 101n,
      scope: 'public.users',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 0x01),
      changeChainHead: Buffer.alloc(32, 0x00),
      createdAtUs: 1723500100000000n,
      protocolVersion: 3,
    };
    const cp2 = {
      checkpointId: '00000000-0000-0000-0000-000000000102',
      commitSeq: 102n,
      scope: 'public.users',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 0x02),
      changeChainHead: Buffer.alloc(32, 0x01),
      createdAtUs: 1723500200000000n,
      protocolVersion: 3,
    };

    // Agent commits during outage -> queued locally!
    const res1 = await agent.commitCheckpoint(cp1, Buffer.alloc(32, 0x11));
    const res2 = await agent.commitCheckpoint(cp2, Buffer.alloc(32, 0x22));

    expect(res1.isSynchronized).toBe(false);
    expect(res2.isSynchronized).toBe(false);
    expect(agent.getOfflineQueueLength()).toBe(2);

    // RESTORE CLOUD CONNECTIVITY
    service.setNetworkOnlineStatus(true);

    // Flush queue
    const drainedCount = await agent.flushQueue();
    expect(drainedCount).toBe(2);
    expect(agent.getOfflineQueueLength()).toBe(0);

    // Verify proof is cached and valid
    const cachedProof2 = agent.getCachedProof(cp2.checkpointId);
    expect(cachedProof2).toBeDefined();
    expect(cachedProof2?.commitment.commitSeq).toBe('102');
  });
});
