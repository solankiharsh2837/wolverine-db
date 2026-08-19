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
} from '../src/index.js';

describe('Milestone 2.4 & 2.5 — Non-Equivocation Locking, Slashing Evidence & Crash Recovery', () => {
  const testDir = path.join(process.cwd(), 'tmp', 'test_equiv_crash');
  const journalPath = path.join(testDir, `crash_journal_${Date.now()}.wdbjrn`);

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
    customPayload: string,
    prevDigestHex: string = '0000000000000000000000000000000000000000000000000000000000000000'
  ): CanonicalCommitment {
    const unsigned = {
      commitmentId: `cmt-${seq}-${customPayload}`,
      tenantId: 'enterprise_bank',
      databaseId: 'core_db',
      epoch: 1,
      commitSeq: seq,
      checkpointDigestHex: crypto.createHash('sha256').update(`chk_${customPayload}`).digest('hex'),
      stateMerkleRootHex: crypto.createHash('sha256').update(`root_${customPayload}`).digest('hex'),
      changeChainHeadHex: crypto.createHash('sha256').update(`chain_${customPayload}`).digest('hex'),
      logicalTimestampUs: 1723800000000000n,
      lsn: '0/1700100',
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
        keyId: 'kms-01',
        customerPubkeyHex: customerPubkey.toString('hex'),
        signatureHex: custSig.toString('hex'),
        commitSeq: seq,
      },
    };
  }

  it('1. Non-Equivocation Lock: conflicting commitment for same sequence triggers EQUIVOCATION_DETECTED and records slashing evidence', async () => {
    const sm = new FormalValidatorStateMachine('val-01', valKeypairs[0]!.privateKey, valSetManager, undefined, agentPubkey, customerPubkey);
    await sm.initialize();

    const cmtA = makeCommitment(1842n, 'HONEST_TRANSACTION');
    const attA = await sm.attestCommitment(cmtA);
    expect(attA.commitSeq).toBe(1842n);

    // Present conflicting commitment B for the exact same sequence 1842
    const cmtB = makeCommitment(1842n, 'MALICIOUS_FORK');

    await expect(sm.attestCommitment(cmtB)).rejects.toThrowError(
      /EQUIVOCATION_DETECTED/
    );

    const slashingEvidence = sm.getSlashingEvidence();
    expect(slashingEvidence.length).toBe(1);
    expect(slashingEvidence[0]!.evidenceType).toBe('EQUIVOCATION_DETECTED');
    expect(slashingEvidence[0]!.commitSeq).toBe(1842n);
    expect(slashingEvidence[0]!.observedDigestAHex).toBe(attA.commitmentDigestHex);
    expect(slashingEvidence[0]!.observedDigestBHex).not.toBe(attA.commitmentDigestHex);
  });

  it('2. Crash Recovery & Durability: validator restarts after fsync, restores locks from disk, and prevents equivocation', async () => {
    const journal1 = new ValidatorDurableJournal('val-01', journalPath);
    const sm1 = new FormalValidatorStateMachine('val-01', valKeypairs[0]!.privateKey, valSetManager, journal1, agentPubkey, customerPubkey);
    await sm1.initialize();

    const cmtA = makeCommitment(100n, 'STATE_A');
    const attA = await sm1.attestCommitment(cmtA);

    expect(sm1.sequence).toBe(100n);
    await journal1.close();

    // SIMULATE CRASH & RESTART: New validator instance with same journal file
    const journal2 = new ValidatorDurableJournal('val-01', journalPath);
    const sm2 = new FormalValidatorStateMachine('val-01', valKeypairs[0]!.privateKey, valSetManager, journal2, agentPubkey, customerPubkey);
    await sm2.initialize();

    // Assert that sequence 100 was remembered from disk
    expect(sm2.sequence).toBe(100n);

    // Resubmitting cmtA should return identical cached attestation
    const attAResubmit = await sm2.attestCommitment(cmtA);
    expect(attAResubmit.signatureHex).toBe(attA.signatureHex);

    // Presenting conflicting cmtB for seq 100 must be rejected with EQUIVOCATION_DETECTED
    const cmtB = makeCommitment(100n, 'STATE_B');
    await expect(sm2.attestCommitment(cmtB)).rejects.toThrowError(
      /EQUIVOCATION_DETECTED/
    );

    await journal2.close();
  });
});
