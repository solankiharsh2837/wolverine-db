import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  computeTrustCommitmentDigest,
  createSignedCustomerCommitment,
  verifyCustomerCommitment,
  WolverineTrustLedger,
} from '../../src/index.js';

describe('Wolverine Trust Network 10 Mathematical Invariants (WDB-0080..0088)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('Invariant 1 & 2: Same commitment -> identical digest; modified commitment -> different digest', () => {
    const c1 = {
      commitmentId: 'c1',
      tenantId: 't1',
      databaseId: 'd1',
      checkpointId: 'cp1',
      commitSeq: 10n,
      checkpointDigest: Buffer.alloc(32, 0xaa),
      previousTrustCommitment: Buffer.alloc(32, 0),
      protocolVersion: 1,
      logicalTimestamp: 1000n,
      epoch: 1,
      validatorSetId: 'v1',
      customerPubkey: Buffer.alloc(32, 0),
    };

    const d1 = computeTrustCommitmentDigest(c1);
    const d2 = computeTrustCommitmentDigest(c1);
    expect(d1.equals(d2)).toBe(true);

    const cModified = { ...c1, commitSeq: 11n };
    const dModified = computeTrustCommitmentDigest(cModified);
    expect(d1.equals(dModified)).toBe(false);
  });

  it('Invariant 7: Ledger detects sequence fork or modified predecessor', () => {
    const ledger = new WolverineTrustLedger();
    ledger.appendRecord('COMMITMENT', { id: 1 });
    ledger.appendRecord('ATTESTATION', { id: 2 });

    expect(ledger.verifyLedgerIntegrity()).toBe(true);

    const records = ledger.getRecords() as any[];
    // Forge previousRecordDigest
    records[1].previousRecordDigest = Buffer.alloc(32, 0xff);
    expect(ledger.verifyLedgerIntegrity()).toBe(false);
  });
});
