import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WolverineTrustLedger,
  TrustConsensusEngine,
  TrustValidator,
  createSignedCustomerCommitment,
} from '../../src/index.js';

describe('Validator Attestation & Quorum Consensus (WDB-0083, WDB-0084)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('consensus quorum: achieves FINALIZED state when M-of-N validators attest', () => {
    const ledger = new WolverineTrustLedger();
    const consensus = new TrustConsensusEngine(ledger, 3, 5);

    const val1 = new TrustValidator('v1');
    const val2 = new TrustValidator('v2');
    const val3 = new TrustValidator('v3');
    const val4 = new TrustValidator('v4');
    const val5 = new TrustValidator('v5');

    consensus.registerValidatorKey('v1', val1.publicKey);
    consensus.registerValidatorKey('v2', val2.publicKey);
    consensus.registerValidatorKey('v3', val3.publicKey);
    consensus.registerValidatorKey('v4', val4.publicKey);
    consensus.registerValidatorKey('v5', val5.publicKey);

    const customer = genKeys();
    const commitment = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId: 'tenant-enterprise',
        databaseId: 'db-primary',
        checkpointId: 'chk-01',
        commitSeq: 1n,
        checkpointDigest: Buffer.alloc(32, 0xaa),
        previousTrustCommitment: Buffer.alloc(32, 0),
      },
      customer.priv,
      customer.pub
    );

    // 4 out of 5 validators attest
    const att1 = val1.attestCommitment(commitment, customer.pub);
    const att2 = val2.attestCommitment(commitment, customer.pub);
    const att3 = val3.attestCommitment(commitment, customer.pub);
    const att4 = val4.attestCommitment(commitment, customer.pub);

    const cert = consensus.processAttestations(commitment, [att1, att2, att3, att4]);

    expect(cert.finalityStatus).toBe('FINALIZED');
    expect(cert.quorumCount).toBe(4);
    expect(cert.totalValidators).toBe(5);
  });

  it('fails closed: rejects consensus when quorum threshold is not met', () => {
    const ledger = new WolverineTrustLedger();
    const consensus = new TrustConsensusEngine(ledger, 3, 5);

    const val1 = new TrustValidator('v1');
    const val2 = new TrustValidator('v2');
    consensus.registerValidatorKey('v1', val1.publicKey);
    consensus.registerValidatorKey('v2', val2.publicKey);

    const customer = genKeys();
    const commitment = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId: 'tenant-enterprise',
        databaseId: 'db-primary',
        checkpointId: 'chk-02',
        commitSeq: 2n,
        checkpointDigest: Buffer.alloc(32, 0xbb),
        previousTrustCommitment: Buffer.alloc(32, 0),
      },
      customer.priv,
      customer.pub
    );

    const att1 = val1.attestCommitment(commitment, customer.pub);
    const att2 = val2.attestCommitment(commitment, customer.pub);

    // Only 2 attestations provided (need 3)
    expect(() => consensus.processAttestations(commitment, [att1, att2])).toThrow(
      /CONSENSUS_UNAVAILABLE/
    );
  });
});
