import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WORMCheckpointStore,
  CheckpointAnchorEngine,
  computeCheckpointDigest,
  WolverineTrustNetworkService,
  WolverineEvidenceAgent,
  TrustNetworkRecoveryIntegrator,
} from '../../src/index.js';

describe('Unified Trust Basis Integration with Reconstruction (WDB-0070..0076, WDB-0080..0088)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('unified trust verification: verifies identical digest across Local, WORM Vault, and Trust Network', async () => {
    const vaultStore = new WORMCheckpointStore();
    const service = new WolverineTrustNetworkService(3, 5);
    const customer = genKeys();

    service.registerTenant('tenant-bank', customer.pub, 'db-core');

    const agent = new WolverineEvidenceAgent({
      tenantId: 'tenant-bank',
      databaseId: 'db-core',
      customerPubkey: customer.pub,
      customerPrivateKey: customer.priv,
      service,
    });

    const checkpoint = {
      checkpointId: '00000000-0000-0000-0000-000000001000',
      commitSeq: 1000n,
      scope: 'public.accounts',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 0x10),
      changeChainHead: Buffer.alloc(32, 0x00),
      createdAtUs: 1723500000000000n,
      protocolVersion: 3,
    };

    // Anchor to WORM store
    await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, checkpoint);
    const localDigest = computeCheckpointDigest(checkpoint);

    // Commit to Wolverine Trust Network
    const commitRes = await agent.commitCheckpoint(checkpoint, localDigest);
    const proof = commitRes.proof!;

    // Unified trust verification passes
    const res = await TrustNetworkRecoveryIntegrator.verifyUnifiedTrustBasis(
      checkpoint,
      vaultStore,
      proof
    );
    expect(res.isVerified).toBe(true);
  });

  it('fails closed on trust divergence: rejects recovery when trust proof digest diverges from local checkpoint', async () => {
    const vaultStore = new WORMCheckpointStore();
    const service = new WolverineTrustNetworkService(3, 5);
    const customer = genKeys();

    service.registerTenant('tenant-bank', customer.pub, 'db-core');

    const agent = new WolverineEvidenceAgent({
      tenantId: 'tenant-bank',
      databaseId: 'db-core',
      customerPubkey: customer.pub,
      customerPrivateKey: customer.priv,
      service,
    });

    const checkpoint = {
      checkpointId: '00000000-0000-0000-0000-000000001000',
      commitSeq: 1000n,
      scope: 'public.accounts',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 0x10),
      changeChainHead: Buffer.alloc(32, 0x00),
      createdAtUs: 1723500000000000n,
      protocolVersion: 3,
    };

    await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, checkpoint);

    // Commit a different digest to Trust Network
    const divergentDigest = Buffer.alloc(32, 0x99);
    const commitRes = await agent.commitCheckpoint(checkpoint, divergentDigest);
    const divergentProof = commitRes.proof!;

    await expect(
      TrustNetworkRecoveryIntegrator.verifyUnifiedTrustBasis(checkpoint, vaultStore, divergentProof)
    ).rejects.toThrow(/EXTERNAL_TRUST_DIVERGENCE/);
  });
});
