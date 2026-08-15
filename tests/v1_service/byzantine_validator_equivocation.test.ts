import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  PersistentTrustLedger,
  BftConsensusEngine,
  ByzantineTrustValidator,
  createSignedCustomerCommitment,
} from '../../src/index.js';

describe('Byzantine Fault Tolerance & Validator Slashing (WDB-0101, WDB-0103)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('byzantine tolerance: 1 rogue validator double-signs -> excluded and slashed, 4/5 honest quorum finalizes', async () => {
    const ledger = new PersistentTrustLedger();
    const consensusEngine = new BftConsensusEngine(ledger, 5, 4);

    const validators: ByzantineTrustValidator[] = [];
    for (let i = 1; i <= 5; i++) {
      const v = new ByzantineTrustValidator({
        validatorId: `val-node-0${i}`,
        validatorSetId: 'valset-prod-v1',
        epoch: 1,
        port: 9200 + i,
        host: '127.0.0.1',
      });
      validators.push(v);
      consensusEngine.registerValidatorKey(v.config.validatorId, v.publicKey);
    }

    const customer = genKeys();
    const commitment = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId: 'tenant-bft',
        databaseId: 'ledger-db',
        checkpointId: '00000000-0000-0000-0000-000000000100',
        commitSeq: 100n,
        checkpointDigest: Buffer.alloc(32, 0x11),
        previousTrustCommitment: Buffer.alloc(32, 0),
      },
      customer.priv,
      customer.pub
    );

    // 4 Honest validators attest valid commitment
    const attestations = [];
    for (let i = 0; i < 4; i++) {
      attestations.push(validators[i]!.attestCommitment(commitment, customer.pub));
    }

    // 1 Byzantine validator (val-node-05) signs a conflicting / rogue digest
    const rogueAttestation = {
      commitmentId: commitment.commitmentId,
      validatorId: 'val-node-05',
      validatorSetId: 'valset-prod-v1',
      observedCommitmentDigest: Buffer.alloc(32, 0x99), // Conflicting digest!
      attestationSequence: 1n,
      timestampUs: BigInt(Date.now()) * 1000n,
      signature: Buffer.alloc(64, 0xaa),
    };
    attestations.push(rogueAttestation);

    // Process consensus
    const certificate = await consensusEngine.processAttestations(commitment, attestations);

    // Verified: Exactly 4 valid attestations accepted, rogue signature excluded
    expect(certificate.quorumCount).toBe(4);
    expect(certificate.finalityStatus).toBe('FINALIZED');

    // Slashing records recorded for rogue validator
    const slashingRecords = consensusEngine.getSlashingRecords();
    expect(slashingRecords.length).toBe(1);
    expect(slashingRecords[0]?.offendingValidatorId).toBe('val-node-05');
    expect(slashingRecords[0]?.proofType).toBe('DOUBLE_SIGNING');
  });
});
