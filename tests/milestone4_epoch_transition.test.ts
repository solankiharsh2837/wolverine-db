import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  ValidatorSetManager,
  QuorumAggregator,
  CanonicalCommitment,
  computeCanonicalCommitmentDigest,
  computeAgentAttestationDigest,
  computeCustomerAuthorizationDigest,
  CrossEpochTransitionCertificate,
  computeEpochTransitionDigest,
  verifyEpochTransitionCertificate,
  deriveNewEpochGenesisDigest,
  FormalValidatorStateMachine,
  SoftwareCustomerSigner,
} from '../src/index.js';

describe('Milestone 4.1, 4.2 & 4.3 — Cross-Epoch Transition Certificate (TC_{e -> e+1}) & Validator Rotation', () => {
  const agentKeypair = crypto.generateKeyPairSync('ed25519');
  const customerKeypair = crypto.generateKeyPairSync('ed25519');

  const agentPubkey = agentKeypair.publicKey.export({ format: 'der', type: 'spki' });
  const customerPubkey = customerKeypair.publicKey.export({ format: 'der', type: 'spki' });

  // Validator Set 1 (Epoch 1)
  const val1Keypairs = [
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
  ];
  const valSet1 = new ValidatorSetManager({
    validatorSetId: 'valset-epoch-01',
    epoch: 1,
    quorumThreshold: 4,
    totalValidators: 5,
    validators: val1Keypairs.map((kp, idx) => ({
      validatorId: `v1-node-0${idx + 1}`,
      publicKeyHex: kp.publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
      weight: 1,
    })),
  });

  // Validator Set 2 (Epoch 2 - new key material)
  const val2Keypairs = [
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
  ];
  const valSet2 = new ValidatorSetManager({
    validatorSetId: 'valset-epoch-02',
    epoch: 2,
    quorumThreshold: 4,
    totalValidators: 5,
    validators: val2Keypairs.map((kp, idx) => ({
      validatorId: `v2-node-0${idx + 1}`,
      publicKeyHex: kp.publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
      weight: 1,
    })),
  });

  function makeEpoch1Commitment(seq: bigint): CanonicalCommitment {
    const unsigned = {
      commitmentId: `cmt-e1-${seq}`,
      tenantId: 'enterprise_bank',
      databaseId: 'core_ledger',
      epoch: 1,
      commitSeq: seq,
      checkpointDigestHex: crypto.createHash('sha256').update(`chk_e1_${seq}`).digest('hex'),
      stateMerkleRootHex: crypto.createHash('sha256').update(`root_e1_${seq}`).digest('hex'),
      changeChainHeadHex: crypto.createHash('sha256').update(`chain_e1_${seq}`).digest('hex'),
      logicalTimestampUs: 1723800000000000n,
      lsn: '0/1600100',
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

  function makeTransitionCert(
    oldFinalQC: any,
    newValSet: ValidatorSetManager,
    custKey: crypto.KeyObject
  ): CrossEpochTransitionCertificate {
    const partial = {
      certificateVersion: 2,
      oldEpoch: 1,
      newEpoch: 2,
      oldValidatorSetId: 'valset-epoch-01',
      newValidatorSetId: newValSet.validatorSetId,
      lastFinalizedSeq_old: oldFinalQC.commitSeq,
      lastFinalizedDigest_oldHex: oldFinalQC.commitmentDigestHex,
      newGenesisSeq: 0n,
      transitionReason: 'SCHEDULED_ANNUAL_VALIDATOR_KEY_ROTATION',
      transitionTimestampUs: BigInt(Date.now()) * 1000n,
      oldEpochFinalQC: oldFinalQC,
      customerAuthorization: {
        keyId: 'kms-root-01',
        customerPubkeyHex: custKey.export({ format: 'der', type: 'spki' }).toString('hex'),
        signatureHex: '',
      },
    };

    const transDigest = computeEpochTransitionDigest(partial);
    const authPreimage = Buffer.concat([
      Buffer.from('WDB:CUST_EPOCH_AUTH:v1:', 'utf8'),
      transDigest,
      Buffer.from(newValSet.validatorSetId, 'utf8'),
    ]);
    const authDigest = crypto.createHash('sha256').update(authPreimage).digest();
    const sig = crypto.sign(null, authDigest, customerKeypair.privateKey);

    partial.customerAuthorization.signatureHex = sig.toString('hex');
    const finalDigest = computeEpochTransitionDigest(partial);

    return {
      ...partial,
      transitionCertificateDigestHex: finalDigest.toString('hex'),
    };
  }

  it('1. Cross-Epoch Transition Certificate: binds final QC from Epoch 1 and authorizes Epoch 2 validator set', async () => {
    // 1. Finalize Commit #1842 in Epoch 1
    const v1Sm = val1Keypairs.map(
      (kp, idx) =>
        new FormalValidatorStateMachine(`v1-node-0${idx + 1}`, kp.privateKey, valSet1, undefined, agentPubkey, customerPubkey)
    );
    for (const v of v1Sm) await v.initialize();

    const cmt1842 = makeEpoch1Commitment(1842n);
    const atts = await Promise.all(v1Sm.map((v) => v.attestCommitment(cmt1842)));
    const qc1842 = QuorumAggregator.aggregate(cmt1842, atts, valSet1);

    // 2. Generate TC_{1 -> 2}
    const tc = makeTransitionCert(qc1842, valSet2, customerKeypair.publicKey);

    expect(tc.oldEpoch).toBe(1);
    expect(tc.newEpoch).toBe(2);
    expect(tc.transitionCertificateDigestHex.length).toBe(64);

    // 3. Verify TC_{1 -> 2}
    const result = verifyEpochTransitionCertificate(tc, valSet1, valSet2.getActiveSet(), customerPubkey);
    expect(result.valid).toBe(true);
    expect(result.newGenesisDigest.length).toBe(32);
  });

  it('2. Old Validator Epoch Isolation: old validator from V1 cannot sign Epoch 2 commitment', async () => {
    // Validator from Set 1 (active in epoch 1)
    const oldValSm = new FormalValidatorStateMachine(
      'v1-node-01',
      val1Keypairs[0]!.privateKey,
      valSet1,
      undefined,
      agentPubkey,
      customerPubkey
    );
    await oldValSm.initialize();

    // Create commitment claiming to be Epoch 2
    const unsigned = {
      commitmentId: 'cmt-e2-1',
      tenantId: 'enterprise_bank',
      databaseId: 'core_ledger',
      epoch: 2, // EPOCH 2
      commitSeq: 1n,
      checkpointDigestHex: crypto.createHash('sha256').update('chk_e2_1').digest('hex'),
      stateMerkleRootHex: crypto.createHash('sha256').update('root_e2_1').digest('hex'),
      changeChainHeadHex: crypto.createHash('sha256').update('chain_e2_1').digest('hex'),
      logicalTimestampUs: 1723800000000000n,
      lsn: '0/2000000',
      previousCommitmentDigestHex: '0000000000000000000000000000000000000000000000000000000000000000',
    };
    const cmtDigest = computeCanonicalCommitmentDigest(unsigned);
    const agentDigest = computeAgentAttestationDigest(cmtDigest, unsigned.lsn);
    const custDigest = computeCustomerAuthorizationDigest(cmtDigest, 1n);

    const cmtEpoch2: CanonicalCommitment = {
      ...unsigned,
      agentAttestation: {
        agentNodeId: 'node-01',
        agentPubkeyHex: agentPubkey.toString('hex'),
        signatureHex: crypto.sign(null, agentDigest, agentKeypair.privateKey).toString('hex'),
        lsn: unsigned.lsn,
      },
      customerAuthorization: {
        keyId: 'kms-01',
        customerPubkeyHex: customerPubkey.toString('hex'),
        signatureHex: crypto.sign(null, custDigest, customerKeypair.privateKey).toString('hex'),
        commitSeq: 1n,
      },
    };

    // Old validator active in Epoch 1 MUST reject Epoch 2 commitment
    await expect(oldValSm.attestCommitment(cmtEpoch2)).rejects.toThrowError(
      /Epoch mismatch: validator active in epoch 1, commitment from epoch 2/
    );
  });

  it('3. Unauthorized Epoch Rotation Rejection: attempting to rotate without valid customer signature fails', async () => {
    const v1Sm = val1Keypairs.map(
      (kp, idx) =>
        new FormalValidatorStateMachine(`v1-node-0${idx + 1}`, kp.privateKey, valSet1, undefined, agentPubkey, customerPubkey)
    );
    for (const v of v1Sm) await v.initialize();

    const cmt1842 = makeEpoch1Commitment(1842n);
    const atts = await Promise.all(v1Sm.map((v) => v.attestCommitment(cmt1842)));
    const qc1842 = QuorumAggregator.aggregate(cmt1842, atts, valSet1);

    const tc = makeTransitionCert(qc1842, valSet2, customerKeypair.publicKey);

    // Tamper with customer signature in TC
    tc.customerAuthorization.signatureHex = Buffer.alloc(64, 0xee).toString('hex');
    const newDig = computeEpochTransitionDigest(tc);
    tc.transitionCertificateDigestHex = newDig.toString('hex');

    expect(() =>
      verifyEpochTransitionCertificate(tc, valSet1, valSet2.getActiveSet(), customerPubkey)
    ).toThrowError(/Customer root authorization signature for epoch transition failed/);
  });
});
