import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  DistributedTrustCluster,
  WolverineEvidenceAgentClient,
  OfflineTrustProofVerifier,
  WolverineRuntimeCli,
} from '../../src/index.js';

describe('Distributed Trust Network Runtime Cluster (WDB-0090, WDB-0091, WDB-0092, WDB-0093)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('end-to-end distributed flow: Gateway routes to 5 Validator daemons and replicates across 3 Ledger nodes', async () => {
    const cluster = new DistributedTrustCluster({
      requiredQuorum: 4,
      totalValidators: 5,
      totalReplicas: 3,
    });

    const customer = genKeys();
    cluster.gateway.registerTenant('tenant-enterprise-01', customer.pub, 'production-db');

    const client = new WolverineEvidenceAgentClient({
      tenantId: 'tenant-enterprise-01',
      databaseId: 'production-db',
      customerPubkey: customer.pub,
      customerPrivateKey: customer.priv,
      gateway: cluster.gateway,
    });

    const checkpoint = {
      checkpointId: '00000000-0000-0000-0000-000000001842',
      commitSeq: 1842n,
      scope: 'public.orders',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 0x88),
      changeChainHead: Buffer.alloc(32, 0x11),
      createdAtUs: 1723500000000000n,
      protocolVersion: 3,
    };
    const checkpointDigest = Buffer.alloc(32, 0x5a);

    // Client commits checkpoint over network transport
    const commitRes = await client.commitCheckpoint(checkpoint, checkpointDigest);
    expect(commitRes.isSynchronized).toBe(true);
    expect(commitRes.proof).toBeDefined();

    const proof = commitRes.proof!;
    expect(proof.quorumCertificate.quorumCount).toBe(5); // All 5 daemons attested
    expect(proof.ledgerRecord.ledgerSeq).toBe('1');

    // Verify all 3 Ledger replicas received the finalized record
    for (const replica of cluster.replicas.values()) {
      const records = replica.getLedger().getRecords();
      expect(records.length).toBe(1);
      expect(records[0]?.recordType).toBe('FINALIZATION');
      expect(records[0]?.payload['commitSeq']).toBe('1842');
    }

    // Verify Offline Verifiability
    const offlineResult = OfflineTrustProofVerifier.verifyPortableProof(proof);
    expect(offlineResult.isValid).toBe(true);
    expect(offlineResult.status).toBe('VALID');

    // CLI Status inspection
    const statusOutput = WolverineRuntimeCli.executeClusterStatus(cluster);
    expect(statusOutput).toContain('WOLVERINE DISTRIBUTED TRUST CLUSTER');
    expect(statusOutput).toContain('Active Validators:        5 Daemons');
    expect(statusOutput).toContain('Active Ledger Replicas:   3 Nodes');
  });
});
