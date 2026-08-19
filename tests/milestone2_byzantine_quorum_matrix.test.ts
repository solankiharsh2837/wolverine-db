import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  FormalValidatorStateMachine,
  ValidatorSetManager,
  QuorumAggregator,
  IndependentQuorumVerifier,
  CanonicalCommitment,
  computeCanonicalCommitmentDigest,
  computeAgentAttestationDigest,
  computeCustomerAuthorizationDigest,
  computeCanonicalQuorumCertificateDigest,
} from '../src/index.js';

describe('Milestone 2.7, 2.8 & 2.9 — Byzantine Quorum Matrix (N=5, M=4) & Zero-Trust Verification', () => {
  const agentKeypair = crypto.generateKeyPairSync('ed25519');
  const customerKeypair = crypto.generateKeyPairSync('ed25519');

  const agentPubkey = agentKeypair.publicKey.export({ format: 'der', type: 'spki' });
  const customerPubkey = customerKeypair.publicKey.export({ format: 'der', type: 'spki' });

  // 5 Validators
  const valKeypairs = [
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
  ];

  const valNodes = valKeypairs.map((kp, idx) => ({
    validatorId: `val-0${idx + 1}`,
    publicKeyHex: kp.publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
    weight: 1,
  }));

  const valSetManager = new ValidatorSetManager({
    validatorSetId: 'valset-cluster-v2',
    epoch: 1,
    quorumThreshold: 4,
    totalValidators: 5,
    validators: valNodes,
  });

  function makeCommitment(seq: bigint, stateTag: string = 'REAL'): CanonicalCommitment {
    const unsigned = {
      commitmentId: `cmt-${seq}-${stateTag}`,
      tenantId: 'enterprise_bank',
      databaseId: 'core_ledger',
      epoch: 1,
      commitSeq: seq,
      checkpointDigestHex: crypto.createHash('sha256').update(`chk_${seq}_${stateTag}`).digest('hex'),
      stateMerkleRootHex: crypto.createHash('sha256').update(`root_${seq}_${stateTag}`).digest('hex'),
      changeChainHeadHex: crypto.createHash('sha256').update(`chain_${seq}_${stateTag}`).digest('hex'),
      logicalTimestampUs: 1723800000000000n,
      lsn: `0/${(1600000n + seq * 100n).toString(16)}`,
      previousCommitmentDigestHex: '0000000000000000000000000000000000000000000000000000000000000000',
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

  it('1. Standard 4-of-5 Quorum Certificate & Zero-Trust Verification: reaches finality and passes independent verification', async () => {
    // Instantiate 5 validators
    const validators = valKeypairs.map(
      (kp, idx) =>
        new FormalValidatorStateMachine(`val-0${idx + 1}`, kp.privateKey, valSetManager, undefined, agentPubkey, customerPubkey)
    );
    for (const v of validators) await v.initialize();

    const cmt = makeCommitment(1n);

    // Collect attestations from all 5
    const attestations = await Promise.all(validators.map((v) => v.attestCommitment(cmt)));
    expect(attestations.length).toBe(5);

    // Gateway aggregates QC
    const qc = QuorumAggregator.aggregate(cmt, attestations, valSetManager);

    expect(qc.quorumCount).toBe(5);
    expect(qc.certificateVersion).toBe(2);
    expect(qc.certificateDigestHex.length).toBe(64);

    // Zero-Trust Independent Verifier checks QC
    const verification = IndependentQuorumVerifier.verify(qc, valSetManager);
    expect(verification.valid).toBe(true);
    expect(verification.verifiedSignatures).toBe(5);
  });

  it('2. Test A — One Rogue Byzantine Validator: 4 honest validators achieve QC while rogue signature is rejected', async () => {
    const validators = valKeypairs.map(
      (kp, idx) =>
        new FormalValidatorStateMachine(`val-0${idx + 1}`, kp.privateKey, valSetManager, undefined, agentPubkey, customerPubkey)
    );
    for (const v of validators) await v.initialize();

    const cmtReal = makeCommitment(1842n, 'REAL');
    const cmtAttack = makeCommitment(1842n, 'ATTACK');

    // V1..V4 sign cmtReal; V5 signs cmtAttack
    const att1 = await validators[0]!.attestCommitment(cmtReal);
    const att2 = await validators[1]!.attestCommitment(cmtReal);
    const att3 = await validators[2]!.attestCommitment(cmtReal);
    const att4 = await validators[3]!.attestCommitment(cmtReal);
    const att5Rogue = await validators[4]!.attestCommitment(cmtAttack);

    // Quorum for cmtReal with 4 honest signatures succeeds
    const qcReal = QuorumAggregator.aggregate(cmtReal, [att1, att2, att3, att4, att5Rogue], valSetManager);
    expect(qcReal.quorumCount).toBe(4);
    expect(IndependentQuorumVerifier.verify(qcReal, valSetManager).valid).toBe(true);

    // Attempting to aggregate QC for cmtAttack with only 1 signature fails
    expect(() => QuorumAggregator.aggregate(cmtAttack, [att1, att2, att3, att4, att5Rogue], valSetManager)).toThrowError(
      /CONSENSUS_UNAVAILABLE: Insufficient validator signatures/
    );
  });

  it('3. Test B — Gateway Split-Brain / Equivocation Attempt: neither partition reaches quorum (2/5 and 3/5)', async () => {
    const validators = valKeypairs.map(
      (kp, idx) =>
        new FormalValidatorStateMachine(`val-0${idx + 1}`, kp.privateKey, valSetManager, undefined, agentPubkey, customerPubkey)
    );
    for (const v of validators) await v.initialize();

    const cmtA = makeCommitment(1842n, 'SPLIT_A');
    const cmtB = makeCommitment(1842n, 'SPLIT_B');

    // Gateway sends cmtA to V1, V2
    const att1 = await validators[0]!.attestCommitment(cmtA);
    const att2 = await validators[1]!.attestCommitment(cmtA);

    // Gateway sends cmtB to V3, V4, V5
    const att3 = await validators[2]!.attestCommitment(cmtB);
    const att4 = await validators[3]!.attestCommitment(cmtB);
    const att5 = await validators[4]!.attestCommitment(cmtB);

    const allAttestations = [att1, att2, att3, att4, att5];

    // Attempting to form QC for cmtA (only 2/5 signatures)
    expect(() => QuorumAggregator.aggregate(cmtA, allAttestations, valSetManager)).toThrowError(
      /CONSENSUS_UNAVAILABLE: Insufficient validator signatures/
    );

    // Attempting to form QC for cmtB (only 3/5 signatures)
    expect(() => QuorumAggregator.aggregate(cmtB, allAttestations, valSetManager)).toThrowError(
      /CONSENSUS_UNAVAILABLE: Insufficient validator signatures/
    );
  });

  it('4. Test H — Byzantine Two-Validator Coalition: 2 Byzantine + 3 Honest results in 0 Quorum Certificates (Fail-Closed)', async () => {
    const validators = valKeypairs.map(
      (kp, idx) =>
        new FormalValidatorStateMachine(`val-0${idx + 1}`, kp.privateKey, valSetManager, undefined, agentPubkey, customerPubkey)
    );
    for (const v of validators) await v.initialize();

    const cmtAttack = makeCommitment(1842n, 'ATTACK');
    const cmtReal = makeCommitment(1842n, 'REAL');

    // V1, V2 sign cmtAttack; V3, V4, V5 sign cmtReal
    const att1 = await validators[0]!.attestCommitment(cmtAttack);
    const att2 = await validators[1]!.attestCommitment(cmtAttack);
    const att3 = await validators[2]!.attestCommitment(cmtReal);
    const att4 = await validators[3]!.attestCommitment(cmtReal);
    const att5 = await validators[4]!.attestCommitment(cmtReal);

    // Attack has 2/5 -> Rejected
    expect(() => QuorumAggregator.aggregate(cmtAttack, [att1, att2, att3, att4, att5], valSetManager)).toThrowError(
      /CONSENSUS_UNAVAILABLE/
    );

    // Real has 3/5 -> Rejected (Threshold is 4)
    expect(() => QuorumAggregator.aggregate(cmtReal, [att1, att2, att3, att4, att5], valSetManager)).toThrowError(
      /CONSENSUS_UNAVAILABLE/
    );
  });

  it('5. Quorum Certificate Integrity Tamper Defense: altering QC envelope or signature fails independent verification', async () => {
    const validators = valKeypairs.map(
      (kp, idx) =>
        new FormalValidatorStateMachine(`val-0${idx + 1}`, kp.privateKey, valSetManager, undefined, agentPubkey, customerPubkey)
    );
    for (const v of validators) await v.initialize();

    const cmt = makeCommitment(1n);
    const attestations = await Promise.all(validators.map((v) => v.attestCommitment(cmt)));
    const qc = QuorumAggregator.aggregate(cmt, attestations, valSetManager);

    // 1. Corrupt certificate digest
    const qcCorruptDigest = { ...qc, certificateDigestHex: Buffer.alloc(32, 0xff).toString('hex') };
    expect(() => IndependentQuorumVerifier.verify(qcCorruptDigest, valSetManager)).toThrowError(
      /Quorum certificate digest envelope integrity check failed/
    );

    // 2. Corrupt one validator signature in QC
    const qcCorruptSig = {
      ...qc,
      attestations: qc.attestations.map((a, i) =>
        i === 0 ? { ...a, signatureHex: Buffer.alloc(64, 0xee).toString('hex') } : a
      ),
    };
    // Recompute envelope digest for modified payload
    const newDig = computeCanonicalQuorumCertificateDigest(qcCorruptSig);
    const qcCorruptSigEnvelope = { ...qcCorruptSig, certificateDigestHex: newDig.toString('hex') };

    expect(() => IndependentQuorumVerifier.verify(qcCorruptSigEnvelope, valSetManager)).toThrowError(
      /Invalid cryptographic signature for validator/
    );
  });
});
