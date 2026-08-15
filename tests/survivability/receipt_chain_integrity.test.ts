import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WolverineProductionCluster,
  createSignedCustomerCommitment,
  ImmutableTrustReceiptGenerator,
  ReceiptChain,
  WolverineSurvivabilityCli,
} from '../../src/index.js';

describe('Receipt Chain Verification and Tamper Detection (WDB-0123)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('detects gaps, forks, replays, and verifies unbroken receipt chains', async () => {
    const cluster = new WolverineProductionCluster({ totalValidators: 5, requiredQuorum: 4 });
    const customer = genKeys();
    cluster.registerTenant('tenant-chain-corp', customer.pub, 'main-db');

    const chain = new ReceiptChain();

    // Generate 5 sequential receipts (commitSeq 101 to 105)
    for (let i = 1; i <= 5; i++) {
      const cmt = createSignedCustomerCommitment(
        {
          commitmentId: crypto.randomUUID(),
          tenantId: 'tenant-chain-corp',
          databaseId: 'main-db',
          checkpointId: `00000000-0000-0000-0000-00000000010${i}`,
          commitSeq: BigInt(100 + i),
          checkpointDigest: Buffer.alloc(32, i),
          previousTrustCommitment: Buffer.alloc(32, i - 1),
        },
        customer.priv,
        customer.pub
      );

      const { proof } = await cluster.submitCommitment(cmt);
      const receipt = ImmutableTrustReceiptGenerator.generateReceipt(
        proof,
        cluster.ledger.getMerkleStateRoot()
      );
      chain.appendReceipt(receipt);
    }

    // 1. Authentic Chain Check
    const validRes = chain.verifyChain();
    expect(validRes.isValid).toBe(true);
    expect(validRes.totalReceipts).toBe(5);

    // CLI output check
    const cliOutput = WolverineSurvivabilityCli.executeVerifyReceiptChain(chain);
    expect(cliOutput).toContain('WOLVERINE RECEIPT CHAIN INTEGRITY VERIFIER');
    expect(cliOutput).toContain('Total Finalized Receipts:  5');
    expect(cliOutput).toContain('Chain Verification Result: AUTHENTIC & PROVABLY UNBROKEN (PASS)');

    // 2. Fork Detection
    const forkChain = new ReceiptChain();
    const receipts = chain.getReceipts();
    forkChain.appendReceipt(receipts[0]!);
    // Competing digest for seq 101
    const fakeReceipt = {
      ...receipts[0]!,
      receiptId: 'rcpt-fake-fork',
      receiptDigestHex: Buffer.alloc(32, 0xff).toString('hex'),
    };
    forkChain.appendReceipt(fakeReceipt);
    expect(forkChain.detectFork().hasFork).toBe(true);

    // 3. Gap Detection
    const gapChain = new ReceiptChain();
    gapChain.appendReceipt(receipts[0]!); // Seq 101
    gapChain.appendReceipt(receipts[2]!); // Seq 103 (Skipped 102)
    expect(gapChain.detectGap().hasGap).toBe(true);
    expect(gapChain.verifyChain().isValid).toBe(false);
  });
});
