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
  BatchAnchorManager,
} from '../src/index.js';

describe('Milestone 5.9 — The Final Adversarial Demonstration (Full 3-Plane System)', () => {
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
    validatorSetId: 'valset-demo-01',
    epoch: 1,
    quorumThreshold: 4,
    totalValidators: 5,
    validators: valKeypairs.map((kp, idx) => ({
      validatorId: `val-${idx + 1}`,
      publicKeyHex: kp.publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
      weight: 1,
    })),
  });

  it('Executes the 5-Stage Cinematic Demonstration: Database Tampered vs Witnessed History Intact', async () => {
    // =========================================================================
    // STAGE 1: ESTABLISH TRUTH
    // =========================================================================
    const initialDbRow = { id: 'acc_101', balance: '10000.00' };

    const frontier = new DeterministicStateFrontier(1);
    const snap: BootstrapSnapshot = {
      snapshotId: 'snap-stage1',
      snapshotLsn: '0/1000000',
      createdAtUs: 1723800000000000n,
      schemaEpoch: 1,
      tables: ['public.accounts'],
      rows: [
        {
          tableName: 'public.accounts',
          primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_101', 'utf8') }],
          values: initialDbRow,
        },
      ],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    };
    frontier.bootstrap(snap);
    const historicalRootHex = frontier.computeStateMerkleRoot().toString('hex');

    const unsigned = {
      commitmentId: 'cmt-demo-1',
      tenantId: 'enterprise_fintech',
      databaseId: 'core_banking',
      epoch: 1,
      commitSeq: 1n,
      checkpointDigestHex: crypto.createHash('sha256').update('chk_1').digest('hex'),
      stateMerkleRootHex: historicalRootHex,
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
        agentNodeId: 'agent-enclave-01',
        agentPubkeyHex: agentPubkey.toString('hex'),
        signatureHex: agentSig.toString('hex'),
        lsn: unsigned.lsn,
      },
      customerAuthorization: {
        keyId: 'kms-root-01',
        customerPubkeyHex: customerPubkey.toString('hex'),
        signatureHex: custSig.toString('hex'),
        commitSeq: 1n,
      },
    };

    // 5/5 Validators Sign
    const vSms = valKeypairs.map(
      (kp, idx) =>
        new FormalValidatorStateMachine(`val-${idx + 1}`, kp.privateKey, valSetManager, undefined, agentPubkey, customerPubkey)
    );
    for (const v of vSms) await v.initialize();

    const atts = await Promise.all(vSms.map((v) => v.attestCommitment(commitment)));
    const qc = QuorumAggregator.aggregate(commitment, atts, valSetManager);

    // Plane 3: Batch Anchor to Base Blockchain
    const anchorManager = new BatchAnchorManager('base-mainnet', valSetManager.validatorSetId, 1, 1);
    const anchorBatch = anchorManager.enqueueQuorumCertificate(qc);

    // Build portable proof package
    const proofPackage = ProofPackageBuilder.buildPackage({
      commitment,
      qc,
      validatorSet: valSetManager.getActiveSet(),
      table: 'public.accounts',
      rowKeyHex: Buffer.from('acc_101', 'utf8').toString('hex'),
      rowValues: initialDbRow,
      anchorBatch: anchorBatch || undefined,
    });

    // =========================================================================
    // STAGE 2: ATTACKER DESTROYS DATABASE
    // =========================================================================
    // Direct SQL update bypassing Wolverine: UPDATE accounts SET balance = '100000000.00'
    const tamperedLiveDbRow = { id: 'acc_101', balance: '100000000.00' };

    // =========================================================================
    // STAGE 3: ATTACKER DESTROYS CLOUD MEMORY
    // =========================================================================
    // Wipes all in-memory processes
    vSms.length = 0;

    // =========================================================================
    // STAGE 4: AIR-GAPPED VERIFICATION & COMPARISON
    // =========================================================================
    const auditReport = AirGappedProofVerifier.verifyPackage(proofPackage, customerPubkey);

    expect(auditReport.valid).toBe(true);
    expect(auditReport.verdict).toBe('AUTHENTIC WOLVERINE TRUST HISTORY');
    expect(auditReport.steps.length).toBe(13);

    const cliOutput = AirGappedProofVerifier.formatCliReport(auditReport, tamperedLiveDbRow);

    // Assert the core thesis:
    expect(cliOutput).toContain('THE DATABASE WAS CHANGED.');
    expect(cliOutput).toContain('THE WITNESSED HISTORY WAS NOT.');
    expect(cliOutput).toContain('DIVERGED');
    expect(cliOutput).toContain('"balance":"10000.00"');
    expect(cliOutput).toContain('"balance":"100000000.00"');
  });
});
