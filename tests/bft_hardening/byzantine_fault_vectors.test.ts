import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WolverineProductionCluster,
  createSignedCustomerCommitment,
  OfflineTrustProofVerifier,
  EpochRotationManager,
} from '../../src/index.js';

describe('Adversarial Byzantine Fault Vectors (WDB-0111, WDB-0112, WDB-0116)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('fault vector 1: stale epoch rejection', async () => {
    const cluster = new WolverineProductionCluster();
    const epochManager = new EpochRotationManager(cluster.ledger, 1);

    await epochManager.advanceEpoch(); // epoch 2
    await epochManager.advanceEpoch(); // epoch 3

    // Commitment generated for epoch 1 (stale, beyond grace period)
    expect(() => epochManager.validateCommitmentEpoch(1)).toThrow(/STALE_EPOCH/);
    expect(epochManager.validateCommitmentEpoch(2)).toBe(true); // Grace period allowed
    expect(epochManager.validateCommitmentEpoch(3)).toBe(true);
  });

  it('fault vector 2: certificate swapping across tenants/sequences fails standalone verification', async () => {
    const cluster = new WolverineProductionCluster({ totalValidators: 5, requiredQuorum: 4 });
    const customer = genKeys();
    cluster.registerTenant('tenant-alpha', customer.pub, 'db-01');

    const cmt = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId: 'tenant-alpha',
        databaseId: 'db-01',
        checkpointId: '00000000-0000-0000-0000-000000001001',
        commitSeq: 1001n,
        checkpointDigest: Buffer.alloc(32, 0x11),
        previousTrustCommitment: Buffer.alloc(32, 0),
      },
      customer.priv,
      customer.pub
    );

    const { proof } = await cluster.submitCommitment(cmt);

    // Attacker modifies commitment commitSeq from 1001 to 9999
    const tamperedProof = {
      ...proof,
      commitment: {
        ...proof.commitment,
        commitSeq: '9999',
      },
    };

    const res = OfflineTrustProofVerifier.verifyPortableProof(tamperedProof);
    expect(res.isValid).toBe(false);
  });
});
