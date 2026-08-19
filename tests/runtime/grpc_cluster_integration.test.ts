import { describe, it, expect, afterAll, beforeAll } from 'vitest';
import crypto from 'node:crypto';
import {
  DistributedTrustCluster,
  TrustCommitment,
  WolverineEvidenceAgentClient,
  OfflineTrustProofVerifier,
  IndependentQuorumVerifier,
  ValidatorSetManager,
} from '../../src/index.js';

describe('Milestone 1 — Full Distributed Cluster over Real HTTP/2 Network Transport', () => {
  let cluster: DistributedTrustCluster;
  const clientKeyPair = crypto.generateKeyPairSync('ed25519');
  const tenantPubkeyHex = clientKeyPair.publicKey.export({ format: 'der', type: 'spki' }).toString('hex');
  const basePort = 19100;

  beforeAll(async () => {
    cluster = await DistributedTrustCluster.create({
      useGrpc: true,
      totalValidators: 5,
      requiredQuorum: 4,
      totalReplicas: 3,
      validatorSetId: 'valset-grpc-integration',
      basePort,
    });
  });

  afterAll(async () => {
    if (cluster) {
      await cluster.stop();
    }
  });

  it('orchestrates end-to-end commitment, 4/5 BFT quorum, and 3-replica replication across HTTP/2 servers', async () => {
    const genKeys = () => {
      const pair = crypto.generateKeyPairSync('ed25519');
      const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
      return { pub, priv: pair.privateKey };
    };

    const customer = genKeys();
    cluster.gateway.registerTenant('tenant-grpc-01', customer.pub, 'db-grpc-01');

    const client = new WolverineEvidenceAgentClient({
      tenantId: 'tenant-grpc-01',
      databaseId: 'db-grpc-01',
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

    // Client commits checkpoint over real HTTP/2 network transport
    const commitRes = await client.commitCheckpoint(checkpoint, checkpointDigest);
    expect(commitRes.isSynchronized).toBe(true);
    expect(commitRes.proof).toBeDefined();

    const proof = commitRes.proof!;
    expect(proof.quorumCertificate.quorumCount).toBe(5); // All 5 daemons attested over HTTP/2
    expect(proof.ledgerRecord.ledgerSeq).toBe('1');

    // Verify all 3 Ledger replicas received the finalized record over HTTP/2
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
  });
});
