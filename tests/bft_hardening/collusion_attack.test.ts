import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WolverineProductionCluster,
  createSignedCustomerCommitment,
  CollusionDefenseEvaluator,
} from '../../src/index.js';

describe('Byzantine Collusion Threat Model: 1 Validator + Gateway + 1 Replica (WDB-0110)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('collusion resistance: attacker controlling 1 Validator + Gateway + 1 Replica CANNOT forge finality', async () => {
    const cluster = new WolverineProductionCluster({ totalValidators: 5, requiredQuorum: 4 });
    const customer = genKeys();
    cluster.registerTenant('enterprise-alpha', customer.pub, 'production-orders');

    // 1. Establish authentic state 1842
    const legitCommitment = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId: 'enterprise-alpha',
        databaseId: 'production-orders',
        checkpointId: '00000000-0000-0000-0000-000000001842',
        commitSeq: 1842n,
        checkpointDigest: Buffer.alloc(32, 0xaa),
        previousTrustCommitment: Buffer.alloc(32, 0),
      },
      customer.priv,
      customer.pub
    );

    await cluster.submitCommitment(legitCommitment);

    // 2. ATTACKER CONTROLS: val-05 + Gateway + Replica-01
    // Attempts to force consensus for forged Checkpoint 1842 (Digest 0xBB)
    const collusionResult = await CollusionDefenseEvaluator.evaluateCollusionAttack(
      cluster.validators,
      cluster.consensusEngine,
      cluster.ledger,
      {
        rogueValidatorId: 'val-05',
        isGatewayCompromised: true,
        rogueReplicaId: 'replica-01',
        targetSequence: 1842n,
        forgedCheckpointDigest: Buffer.alloc(32, 0xbb),
      },
      legitCommitment,
      customer.pub
    );

    expect(collusionResult.isCollusionBlocked).toBe(true);
    expect(collusionResult.honestValidatorsRejectionCount).toBe(4);
    expect(collusionResult.rogueAttestationCount).toBe(1);
    expect(collusionResult.finalityGranted).toBe(false);
    expect(collusionResult.ledgerCorrupted).toBe(false);
  });
});
