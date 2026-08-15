import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  CatastrophicSurvivabilityCluster,
  createSignedCustomerCommitment,
  ImmutableTrustReceiptVerifier,
} from '../../src/index.js';

describe('Customer Disaster Queue and Catastrophic Failure Recovery (WDB-0120, WDB-0126)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('survives gateway + validator destruction, queues mutations, advances epoch, and recovers unbroken chain', async () => {
    const cluster = new CatastrophicSurvivabilityCluster(5, 4);
    const customer = genKeys();
    const tenantId = 'enterprise-catastrophic-test';
    const databaseId = 'orders-db';
    cluster.registerTenant(tenantId, customer.pub, databaseId);

    // 1. Initial State: CommitSeq 5000 finalized
    const cmt5000 = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId,
        databaseId,
        checkpointId: '00000000-0000-0000-0000-000000005000',
        commitSeq: 5000n,
        checkpointDigest: Buffer.alloc(32, 0x50),
        previousTrustCommitment: Buffer.alloc(32, 0),
      },
      customer.priv,
      customer.pub
    );

    const res5000 = await cluster.submitCommitment(cmt5000);
    expect(res5000.receipt.databaseTime.commitSeq).toBe('5000');

    // 2. CATASTROPHIC DISASTER: Gateway DESTROYED + Validator-01 & Validator-02 DESTROYED
    cluster.simulateDisaster({
      destroyGateway: true,
      destroyValidators: ['val-01', 'val-02'],
    });

    expect(cluster.customerSla.getStatus().trustStatus).toBe('TRUST_OUTAGE');

    // 3. Customer continues generating mutations (5001 to 5005) -> Queued locally
    for (let seq = 5001n; seq <= 5005n; seq++) {
      const pendingCmt = createSignedCustomerCommitment(
        {
          commitmentId: crypto.randomUUID(),
          tenantId,
          databaseId,
          checkpointId: `00000000-0000-0000-0000-00000000${seq}`,
          commitSeq: seq,
          checkpointDigest: Buffer.alloc(32, Number(seq % 255n)),
          previousTrustCommitment: Buffer.alloc(32, 0),
        },
        customer.priv,
        customer.pub
      );

      // Attempting to submit throws error (Gateway destroyed), but commitment is safely queued
      await expect(cluster.submitCommitment(pendingCmt)).rejects.toThrow(/DESTROYED/);
    }

    expect(cluster.customerSla.getQueuedCommitments().length).toBe(5);
    expect(cluster.customerSla.getStatus().pendingCommitments).toBe(5);

    // 4. CLUSTER RECOVERY & EPOCH ADVANCEMENT (Epoch 1 -> Epoch 2)
    await cluster.restoreAndAdvanceEpoch(2, 'valset-epoch-2');

    // 5. REPLAY CUSTOMER QUEUE
    const replayedReceipts = await cluster.replayQueuedCustomerCommitments();
    expect(replayedReceipts.length).toBe(5);
    expect(cluster.customerSla.getStatus().pendingCommitments).toBe(0);
    expect(cluster.customerSla.getStatus().trustStatus).toBe('TRUST_CURRENT');

    // 6. VERIFY RECEIPT CHAIN FROM 5000 TO 5005
    const chainVerification = cluster.receiptChain.verifyChain();
    expect(chainVerification.isValid).toBe(true);
    expect(chainVerification.totalReceipts).toBe(6);

    // 7. OFFLINE VERIFIER CHECKS LAST RECEIPT
    const lastReceipt = chainVerification.lastVerifiedReceipt!;
    const offlineResult = ImmutableTrustReceiptVerifier.verifyReceiptOffline(lastReceipt);
    expect(offlineResult.isValid).toBe(true);
    expect(offlineResult.status).toBe('AUTHENTIC_RECEIPT');
  });
});
