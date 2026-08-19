import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  ValidatorSetManager,
  QuorumAggregator,
  CanonicalCommitment,
  computeCanonicalCommitmentDigest,
  computeAgentAttestationDigest,
  computeCustomerAuthorizationDigest,
  ProofPackageBuilder,
  AirGappedProofVerifier,
  FormalValidatorStateMachine,
  DeterministicStateFrontier,
  BootstrapSnapshot,
  MutationOperation,
  canonicalizeJson,
} from '../src/index.js';

describe('Milestone 5.5 & 5.6 — Portable Proof Package & 13-Step Air-Gapped Verifier', () => {
  const agentKeypair = crypto.generateKeyPairSync('ed25519');
  const customerKeypair = crypto.generateKeyPairSync('ed25519');

  const agentPubkey = agentKeypair.publicKey.export({ format: 'der', type: 'spki' });
  const customerPubkey = customerKeypair.publicKey.export({ format: 'der', type: 'spki' });

  const valKeypairs = [
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
  ];

  const valSetManager = new ValidatorSetManager({
    validatorSetId: 'valset-airgap-01',
    epoch: 1,
    quorumThreshold: 4,
    totalValidators: 5,
    validators: valKeypairs.map((kp, idx) => ({
      validatorId: `val-${idx + 1}`,
      publicKeyHex: kp.publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
      weight: 1,
    })),
  });

  async function buildTestPackage() {
    const frontier = new DeterministicStateFrontier(1);
    const snap: BootstrapSnapshot = {
      snapshotId: 'snap-airgap',
      snapshotLsn: '0/1000000',
      createdAtUs: 1723800000000000n,
      schemaEpoch: 1,
      tables: ['public.accounts'],
      rows: [
        {
          tableName: 'public.accounts',
          primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_101', 'utf8') }],
          values: { id: 'acc_101', balance: '10000.00' },
        },
      ],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    };
    frontier.bootstrap(snap);
    const rootHex = frontier.computeStateMerkleRoot().toString('hex');

    const unsigned = {
      commitmentId: 'cmt-airgap-1',
      tenantId: 'enterprise_bank',
      databaseId: 'core_ledger',
      epoch: 1,
      commitSeq: 1n,
      checkpointDigestHex: crypto.createHash('sha256').update('chk_1').digest('hex'),
      stateMerkleRootHex: rootHex,
      changeChainHeadHex: crypto.createHash('sha256').update('chain_1').digest('hex'),
      logicalTimestampUs: 1723800000000000n,
      lsn: '0/1000100',
      previousCommitmentDigestHex: '00'.repeat(32),
    };

    const cmtDigest = computeCanonicalCommitmentDigest(unsigned);
    const agentDigest = computeAgentAttestationDigest(cmtDigest, unsigned.lsn);
    const agentSig = crypto.sign(null, agentDigest, agentKeypair.privateKey);

    const custDigest = computeCustomerAuthorizationDigest(cmtDigest, 1n);
    const custSig = crypto.sign(null, custDigest, customerKeypair.privateKey);

    const commitment: CanonicalCommitment = {
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
        commitSeq: 1n,
      },
    };

    const vSms = valKeypairs.map(
      (kp, idx) =>
        new FormalValidatorStateMachine(`val-${idx + 1}`, kp.privateKey, valSetManager, undefined, agentPubkey, customerPubkey)
    );
    for (const v of vSms) await v.initialize();

    const atts = await Promise.all(vSms.map((v) => v.attestCommitment(commitment)));
    const qc = QuorumAggregator.aggregate(commitment, atts, valSetManager);

    const pkg = ProofPackageBuilder.buildPackage({
      commitment,
      qc,
      validatorSet: valSetManager.getActiveSet(),
      table: 'public.accounts',
      rowKeyHex: Buffer.from('acc_101', 'utf8').toString('hex'),
      rowValues: { id: 'acc_101', balance: '10000.00' },
    });

    return { pkg, commitment, qc, rootHex };
  }

  it('1. Air-Gapped Verification: 13-step offline verification completes with AUTHENTIC WOLVERINE TRUST HISTORY', async () => {
    const { pkg } = await buildTestPackage();

    const report = AirGappedProofVerifier.verifyPackage(pkg, customerPubkey);

    expect(report.valid).toBe(true);
    expect(report.verdict).toBe('AUTHENTIC WOLVERINE TRUST HISTORY');
    expect(report.steps.length).toBe(13);

    for (const step of report.steps) {
      expect(step.passed).toBe(true);
    }

    const formattedOutput = AirGappedProofVerifier.formatCliReport(report, { id: 'acc_101', balance: '10000.00' });
    expect(formattedOutput).toContain('AUTHENTIC WITNESSED RECORD');
    expect(formattedOutput).toContain('SYNCHRONIZED');
  });

  it('2. Tampering Rejection: forged customer authorization signature fails Step 3', async () => {
    const { pkg } = await buildTestPackage();

    // Forged customer signature
    pkg.customerAuthorization.signatureHex = Buffer.alloc(64, 0x99).toString('hex');
    // Recompute manifest with canonical JSON
    const { manifestDigestHex, ...body } = pkg;
    pkg.manifestDigestHex = crypto.createHash('sha256').update(Buffer.from(canonicalizeJson(body), 'utf8')).digest('hex');

    const report = AirGappedProofVerifier.verifyPackage(pkg, customerPubkey);
    expect(report.valid).toBe(false);

    const step3 = report.steps.find((s) => s.stepNumber === 3);
    expect(step3?.passed).toBe(false);
  });
});
