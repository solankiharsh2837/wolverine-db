import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  FormalValidatorStateMachine,
  ValidatorSetManager,
  ValidatorDurableJournal,
  CanonicalCommitment,
  computeCanonicalCommitmentDigest,
  computeAgentAttestationDigest,
  computeCustomerAuthorizationDigest,
  ValidatorLifecycleState,
} from '../src/index.js';

describe('Milestone 2.2 & 2.6 — Formal Validator State Machine & Sequence Invariants', () => {
  const testDir = path.join(process.cwd(), 'tmp', 'test_val_sm');
  const journalPath = path.join(testDir, `val_journal_${Date.now()}.wdbjrn`);

  const agentKeypair = crypto.generateKeyPairSync('ed25519');
  const customerKeypair = crypto.generateKeyPairSync('ed25519');
  const valKeypairs = [
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
  ];

  const agentPubkey = agentKeypair.publicKey.export({ format: 'der', type: 'spki' });
  const customerPubkey = customerKeypair.publicKey.export({ format: 'der', type: 'spki' });
  const valPubkey = valKeypairs[0]!.publicKey.export({ format: 'der', type: 'spki' });

  const valSetManager = new ValidatorSetManager({
    validatorSetId: 'valset-genesis',
    epoch: 1,
    quorumThreshold: 4,
    totalValidators: 5,
    validators: valKeypairs.map((kp, idx) => ({
      validatorId: `val-0${idx + 1}`,
      publicKeyHex: kp.publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
      weight: 1,
    })),
  });

  beforeEach(() => {
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  function makeCommitment(
    seq: bigint,
    epoch: number = 1,
    prevDigestHex: string = '0000000000000000000000000000000000000000000000000000000000000000'
  ): CanonicalCommitment {
    const unsigned = {
      commitmentId: `cmt-${seq}`,
      tenantId: 'enterprise_fintech',
      databaseId: 'aurora_prod',
      epoch,
      commitSeq: seq,
      checkpointDigestHex: crypto.createHash('sha256').update(`chk_${seq}`).digest('hex'),
      stateMerkleRootHex: crypto.createHash('sha256').update(`root_${seq}`).digest('hex'),
      changeChainHeadHex: crypto.createHash('sha256').update(`chain_${seq}`).digest('hex'),
      logicalTimestampUs: 1723800000000000n + seq * 1000000n,
      lsn: `0/${(1600000n + seq * 100n).toString(16)}`,
      previousCommitmentDigestHex: prevDigestHex,
    };

    const cmtDigest = computeCanonicalCommitmentDigest(unsigned);

    const agentDigest = computeAgentAttestationDigest(cmtDigest, unsigned.lsn);
    const agentSig = crypto.sign(null, agentDigest, agentKeypair.privateKey);

    const custDigest = computeCustomerAuthorizationDigest(cmtDigest, seq);
    const custSig = crypto.sign(null, custDigest, customerKeypair.privateKey);

    return {
      ...unsigned,
      agentAttestation: {
        agentNodeId: 'node-01',
        agentPubkeyHex: agentPubkey.toString('hex'),
        signatureHex: agentSig.toString('hex'),
        lsn: unsigned.lsn,
      },
      customerAuthorization: {
        keyId: 'kms-key-01',
        customerPubkeyHex: customerPubkey.toString('hex'),
        signatureHex: custSig.toString('hex'),
        commitSeq: seq,
      },
    };
  }

  it('1. Validator Lifecycle & Contiguous Sequence: transitions BOOTING -> READY -> LOCKED -> ATTESTED', async () => {
    const journal = new ValidatorDurableJournal('val-01', journalPath);
    const sm = new FormalValidatorStateMachine('val-01', valKeypairs[0]!.privateKey, valSetManager, journal, agentPubkey, customerPubkey);

    expect(sm.lifecycleState).toBe(ValidatorLifecycleState.BOOTING);
    await sm.initialize();
    expect(sm.lifecycleState).toBe(ValidatorLifecycleState.READY);

    // Commit 1
    const cmt1 = makeCommitment(1n);
    const att1 = await sm.attestCommitment(cmt1);

    expect(sm.lifecycleState).toBe(ValidatorLifecycleState.ATTESTED);
    expect(att1.validatorId).toBe('val-01');
    expect(att1.commitSeq).toBe(1n);
    expect(att1.signatureHex.length).toBe(128); // 64-byte hex

    // Commit 2 (contiguous sequence)
    const cmt2 = makeCommitment(2n, 1, att1.commitmentDigestHex);
    const att2 = await sm.attestCommitment(cmt2);

    expect(att2.commitSeq).toBe(2n);
    expect(sm.sequence).toBe(2n);

    await journal.close();
  });

  it('2. Idempotent Duplicate Submission: duplicate commitment returns same attestation without state divergence', async () => {
    const sm = new FormalValidatorStateMachine('val-01', valKeypairs[0]!.privateKey, valSetManager, undefined, agentPubkey, customerPubkey);
    await sm.initialize();

    const cmt1 = makeCommitment(1n);
    const att1 = await sm.attestCommitment(cmt1);

    // Resubmit identical commitment #1
    const att1Duplicate = await sm.attestCommitment(cmt1);

    expect(att1Duplicate.signatureHex).toBe(att1.signatureHex);
    expect(att1Duplicate.attestationTimestampUs).toBe(att1.attestationTimestampUs);
    expect(sm.sequence).toBe(1n);
  });

  it('3. Sequence Gap Rejection: jumping from seq 1 to seq 5 is rejected fail-closed', async () => {
    const sm = new FormalValidatorStateMachine('val-01', valKeypairs[0]!.privateKey, valSetManager, undefined, agentPubkey, customerPubkey);
    await sm.initialize();

    const cmt1 = makeCommitment(1n);
    const att1 = await sm.attestCommitment(cmt1);

    // Jump to seq 5
    const cmt5 = makeCommitment(5n, 1, att1.commitmentDigestHex);

    await expect(sm.attestCommitment(cmt5)).rejects.toThrowError(
      /Sequence gap rejected: expected 2, observed 5/
    );

    expect(sm.sequence).toBe(1n);
  });

  it('4. Sequence Rollback Rejection: attempting to submit seq 1 after seq 2 is rejected', async () => {
    const sm = new FormalValidatorStateMachine('val-01', valKeypairs[0]!.privateKey, valSetManager, undefined, agentPubkey, customerPubkey);
    await sm.initialize();

    const cmt1 = makeCommitment(1n);
    const att1 = await sm.attestCommitment(cmt1);

    const cmt2 = makeCommitment(2n, 1, att1.commitmentDigestHex);
    await sm.attestCommitment(cmt2);

    // Attempt rollback: submit a different commitment for seq 1
    const cmt1Forged = makeCommitment(1n);
    cmt1Forged.checkpointDigestHex = Buffer.alloc(32, 0xff).toString('hex');
    const cmtDigest = computeCanonicalCommitmentDigest(cmt1Forged);
    const agentDigest = computeAgentAttestationDigest(cmtDigest, cmt1Forged.lsn);
    cmt1Forged.agentAttestation.signatureHex = crypto.sign(null, agentDigest, agentKeypair.privateKey).toString('hex');
    const custDigest = computeCustomerAuthorizationDigest(cmtDigest, 1n);
    cmt1Forged.customerAuthorization.signatureHex = crypto.sign(null, custDigest, customerKeypair.privateKey).toString('hex');

    await expect(sm.attestCommitment(cmt1Forged)).rejects.toThrowError(
      /EQUIVOCATION_DETECTED|Sequence rollback rejected/
    );
  });

  it('5. Predecessor Hash Continuity: rejecting commitment with incorrect predecessor digest', async () => {
    const sm = new FormalValidatorStateMachine('val-01', valKeypairs[0]!.privateKey, valSetManager, undefined, agentPubkey, customerPubkey);
    await sm.initialize();

    const cmt1 = makeCommitment(1n);
    await sm.attestCommitment(cmt1);

    // Commit 2 with forged previousCommitmentDigestHex
    const cmt2ForgedPrev = makeCommitment(2n, 1, Buffer.alloc(32, 0x99).toString('hex'));

    await expect(sm.attestCommitment(cmt2ForgedPrev)).rejects.toThrowError(
      /Predecessor digest mismatch/
    );
  });

  it('6. Epoch Isolation: rejects commitment from mismatched epoch', async () => {
    const sm = new FormalValidatorStateMachine('val-01', valKeypairs[0]!.privateKey, valSetManager, undefined, agentPubkey, customerPubkey);
    await sm.initialize();

    // Validator set is active in epoch 1; submit commitment from epoch 2
    const cmtEpoch2 = makeCommitment(1n, 2);

    await expect(sm.attestCommitment(cmtEpoch2)).rejects.toThrowError(
      /Epoch mismatch: validator active in epoch 1, commitment from epoch 2/
    );
  });
});
