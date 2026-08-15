import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WolverineProductionCluster,
  createSignedCustomerCommitment,
  ImmutableTrustReceiptGenerator,
  ImmutableTrustReceiptVerifier,
  WolverineReceiptCli,
} from '../../src/index.js';

describe('Immutable Trust Receipt Product Primitive (WDB-0114)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('receipt export and standalone offline verification', async () => {
    const cluster = new WolverineProductionCluster({ totalValidators: 5, requiredQuorum: 4 });
    const customer = genKeys();
    cluster.registerTenant('enterprise-fintech', customer.pub, 'transactions-db');

    const commitment = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId: 'enterprise-fintech',
        databaseId: 'transactions-db',
        checkpointId: '00000000-0000-0000-0000-000000001842',
        commitSeq: 1842n,
        checkpointDigest: Buffer.alloc(32, 0xaa),
        previousTrustCommitment: Buffer.alloc(32, 0),
      },
      customer.priv,
      customer.pub
    );

    const { proof } = await cluster.submitCommitment(commitment);
    const merkleRoot = cluster.ledger.getMerkleStateRoot();

    // Generate Commercial Trust Receipt
    const receipt = ImmutableTrustReceiptGenerator.generateReceipt(proof, merkleRoot);

    expect(receipt.receiptVersion).toBe(1);
    expect(receipt.tenantId).toBe('enterprise-fintech');
    expect(receipt.databaseTime.commitSeq).toBe('1842');
    expect(receipt.consensus.quorumCount).toBe(5);

    // Verify Offline
    const verification = ImmutableTrustReceiptVerifier.verifyReceiptOffline(receipt);
    expect(verification.isValid).toBe(true);
    expect(verification.status).toBe('AUTHENTIC_RECEIPT');

    // CLI Verification
    const cliOutput = WolverineReceiptCli.executeVerifyReceipt(receipt);
    expect(cliOutput).toContain('WOLVERINE IMMUTABLE TRUST RECEIPT VERIFIER');
    expect(cliOutput).toContain('Your database can lie. Your audit trail cannot.');
    expect(cliOutput).toContain('Cryptographic Verdict:    AUTHENTIC & IMMUTABLE (PASS)');
  });
});
