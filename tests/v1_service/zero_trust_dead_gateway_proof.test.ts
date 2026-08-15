import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WolverineProductionCluster,
  createSignedCustomerCommitment,
  OfflineTrustProofVerifier,
  WolverineProductionCli,
} from '../../src/index.js';

describe('Dead-Gateway Invariance & Standalone Verification (WDB-0104)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('zero-trust verification: proof remains 100% valid after total Wolverine Gateway destruction', async () => {
    const cluster = new WolverineProductionCluster({ totalValidators: 5, requiredQuorum: 4 });
    const customer = genKeys();
    cluster.registerTenant('enterprise-alpha', customer.pub, 'production-orders');

    // 1. Commit Checkpoint 1842
    const commitment = createSignedCustomerCommitment(
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

    const { proof } = await cluster.submitCommitment(commitment);

    // 2. TOTAL GATEWAY DESTRUCTION
    cluster.setGatewayOnline(false);

    // Gateway submissions now fail closed
    await expect(cluster.submitCommitment(commitment)).rejects.toThrow();

    // 3. STANDALONE VERIFIER INSPECTION (ZERO NETWORK / DEAD GATEWAY)
    const verificationResult = OfflineTrustProofVerifier.verifyPortableProof(proof);
    expect(verificationResult.isValid).toBe(true);
    expect(verificationResult.status).toBe('VALID');

    // CLI Inspection
    const cliOutput = WolverineProductionCli.executeVerifyBft(proof);
    expect(cliOutput).toContain('WOLVERINE STANDALONE ZERO-TRUST PROOF VERIFIER');
    expect(cliOutput).toContain('BFT Quorum Attested:      5 / 5');
    expect(cliOutput).toContain('Gateway Infrastructure:   UNREACHABLE / UNTRUSTED (ZERO SERVER CONTACT)');
  });
});
