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
} from '../src/index.js';

describe('Milestone 6.4 — Malicious Database Administrator (DBA) Attack Matrix', () => {
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
    validatorSetId: 'valset-dba-01',
    epoch: 1,
    quorumThreshold: 4,
    totalValidators: 5,
    validators: valKeypairs.map((kp, idx) => ({
      validatorId: `val-${idx + 1}`,
      publicKeyHex: kp.publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
      weight: 1,
    })),
  });

  async function setupWitnessedHistory() {
    const historicalRow = { id: 'acc_200', balance: '50000.00', status: 'ACTIVE' };
    const frontier = new DeterministicStateFrontier(1);
    frontier.bootstrap({
      snapshotId: 'snap-dba',
      snapshotLsn: '0/1000000',
      createdAtUs: 1723800000000000n,
      schemaEpoch: 1,
      tables: ['public.accounts'],
      rows: [
        {
          tableName: 'public.accounts',
          primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_200', 'utf8') }],
          values: historicalRow,
        },
      ],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    });
    const rootHex = frontier.computeStateMerkleRoot().toString('hex');

    const unsigned = {
      commitmentId: 'cmt-dba-1',
      tenantId: 'enterprise_fintech',
      databaseId: 'core_banking',
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
      rowKeyHex: Buffer.from('acc_200', 'utf8').toString('hex'),
      rowValues: historicalRow,
    });

    return { pkg, historicalRow, rootHex };
  }

  it('1. Malicious Row Deletion: DBA drops row directly in Postgres -> detected as diverged', async () => {
    const { pkg } = await setupWitnessedHistory();

    const report = AirGappedProofVerifier.verifyPackage(pkg, customerPubkey);
    expect(report.valid).toBe(true);

    // Live database row is deleted
    const liveDbState = { id: 'acc_200', _deleted: true };
    const output = AirGappedProofVerifier.formatCliReport(report, liveDbState);

    expect(output).toContain('THE DATABASE WAS CHANGED.');
    expect(output).toContain('THE WITNESSED HISTORY WAS NOT.');
    expect(output).toContain('DIVERGED');
  });

  it('2. Snapshot Rollback Attack: DBA restores pre-transaction backup -> detected as diverged', async () => {
    const { pkg } = await setupWitnessedHistory();

    const report = AirGappedProofVerifier.verifyPackage(pkg, customerPubkey);
    expect(report.valid).toBe(true);

    // Live database rolled back to prior balance
    const rolledBackDbState = { id: 'acc_200', balance: '0.00', status: 'INACTIVE' };
    const output = AirGappedProofVerifier.formatCliReport(report, rolledBackDbState);

    expect(output).toContain('DIVERGED');
    expect(output).toContain('"balance":"50000.00"');
    expect(output).toContain('"balance":"0.00"');
  });
});
