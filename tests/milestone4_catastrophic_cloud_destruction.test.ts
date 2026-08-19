import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
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
  DurableEvidenceJournal,
  DeterministicStateFrontier,
  BootstrapSnapshot,
  TrustCloudRecoveryEngine,
  DurableDisasterQueue,
  DisasterType,
  FormalValidatorStateMachine,
  MutationOperation,
  encodeBinaryRecord,
  computeChangeHash,
} from '../src/index.js';

describe('Milestone 4.5 & 4.8 — Catastrophic Trust Cloud Destruction & Verified Cold Recovery', () => {
  const testDir = path.join(process.cwd(), 'tmp', 'test_cloud_destruction');
  const journalPath = path.join(testDir, 'customer_evidence.wdbjrn');
  const disasterQueuePath = path.join(testDir, 'disasters.wdbjrn');

  const agentKeypair = crypto.generateKeyPairSync('ed25519');
  const customerKeypair = crypto.generateKeyPairSync('ed25519');

  const agentPubkey = agentKeypair.publicKey.export({ format: 'der', type: 'spki' });
  const customerPubkey = customerKeypair.publicKey.export({ format: 'der', type: 'spki' });

  // Epoch 1 Validators
  const val1Keypairs = [
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
  ];
  const valSet1 = new ValidatorSetManager({
    validatorSetId: 'valset-e1',
    epoch: 1,
    quorumThreshold: 4,
    totalValidators: 5,
    validators: val1Keypairs.map((kp, idx) => ({
      validatorId: `v1-node-0${idx + 1}`,
      publicKeyHex: kp.publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
      weight: 1,
    })),
  });

  // Epoch 2 Validators
  const val2Keypairs = [
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
  ];
  const valSet2 = new ValidatorSetManager({
    validatorSetId: 'valset-e2',
    epoch: 2,
    quorumThreshold: 4,
    totalValidators: 5,
    validators: val2Keypairs.map((kp, idx) => ({
      validatorId: `v2-node-0${idx + 1}`,
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

  it('1. Catastrophic Cloud Destruction & Reconstruction: recovers state solely from durable disk evidence and cross-epoch transition', async () => {
    const journal = new DurableEvidenceJournal(journalPath);
    const frontier = new DeterministicStateFrontier(1);

    // Initial state S0
    const snapshot0: BootstrapSnapshot = {
      snapshotId: 'snap-genesis',
      snapshotLsn: '0/1000000',
      createdAtUs: 1723800000000000n,
      schemaEpoch: 1,
      tables: ['public.accounts'],
      rows: [
        {
          tableName: 'public.accounts',
          primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_1', 'utf8') }],
          values: { id: 'acc_1', balance: '1000.00' },
        },
      ],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    };
    frontier.bootstrap(snapshot0);

    // 1. Commit 3 transactions in Epoch 1
    const v1Sm = val1Keypairs.map(
      (kp, idx) =>
        new FormalValidatorStateMachine(`v1-node-0${idx + 1}`, kp.privateKey, valSet1, undefined, agentPubkey, customerPubkey)
    );
    for (const v of v1Sm) await v.initialize();

    const qcs = [];
    let prevCmtDigestHex = '0000000000000000000000000000000000000000000000000000000000000000';

    for (let seq = 1n; seq <= 3n; seq++) {
      const changeRec = {
        formatVersion: 1,
        versionId: '00000000-0000-0000-0000-000000000001',
        transactionId: `tx-${seq}`,
        timestampUs: 1723800000000000n + seq * 1000n,
        tableId: 'public.accounts',
        recordId: Buffer.from(`acc_${seq + 1n}`, 'utf8'),
        operation: MutationOperation.INSERT,
        fieldSet: { id: `acc_${seq + 1n}`, balance: `${seq}000.00` },
        provenance: {},
        previousHash: journal.chainHead,
      };

      const recordBytes = encodeBinaryRecord(
        1,
        [
          { tag: 1, typeTag: 2, payload: Buffer.alloc(8) },
          { tag: 3, typeTag: 5, payload: Buffer.from(changeRec.transactionId, 'utf8') },
          { tag: 5, typeTag: 5, payload: Buffer.from(changeRec.tableId, 'utf8') },
          { tag: 6, typeTag: 6, payload: changeRec.recordId },
          { tag: 8, typeTag: 8, payload: Buffer.from(JSON.stringify(changeRec.fieldSet), 'utf8') },
        ],
        0
      );

      const changeHash = computeChangeHash(recordBytes, changeRec.previousHash);
      await journal.append({
        sequenceNumber: seq,
        lsn: `0/${(1000000n + seq * 100n).toString(16)}`,
        xid: changeRec.transactionId,
        timestampUs: changeRec.timestampUs,
        changeRecord: changeRec,
        recordBytes,
        changeHash,
        previousHash: changeRec.previousHash,
      });

      frontier.applyChangeRecords([changeRec], `0/${(1000000n + seq * 100n).toString(16)}`, seq, changeHash);
      const rootHex = frontier.computeStateMerkleRoot().toString('hex');

      const unsigned = {
        commitmentId: `cmt-e1-${seq}`,
        tenantId: 'enterprise_bank',
        databaseId: 'core_ledger',
        epoch: 1,
        commitSeq: seq,
        checkpointDigestHex: crypto.createHash('sha256').update(`chk_${seq}`).digest('hex'),
        stateMerkleRootHex: rootHex,
        changeChainHeadHex: changeHash.toString('hex'),
        logicalTimestampUs: 1723800000000000n + seq * 1000n,
        lsn: `0/${(1000000n + seq * 100n).toString(16)}`,
        previousCommitmentDigestHex: prevCmtDigestHex,
      };

      const cmtDigest = computeCanonicalCommitmentDigest(unsigned);
      const agentDigest = computeAgentAttestationDigest(cmtDigest, unsigned.lsn);
      const custDigest = computeCustomerAuthorizationDigest(cmtDigest, seq);

      const cmt: CanonicalCommitment = {
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
          commitSeq: seq,
        },
      };

      const atts = await Promise.all(v1Sm.map((v) => v.attestCommitment(cmt)));
      const qc = QuorumAggregator.aggregate(cmt, atts, valSet1);
      qcs.push(qc);
      prevCmtDigestHex = qc.commitmentDigestHex;
    }

    frontier.setSchemaEpoch(2);
    const preDestructionRootHex = frontier.computeStateMerkleRoot().toString('hex');

    // 2. Cross-Epoch Transition TC_{1 -> 2}
    const finalQC = qcs[qcs.length - 1]!;
    const partialTC = {
      certificateVersion: 2,
      oldEpoch: 1,
      newEpoch: 2,
      oldValidatorSetId: valSet1.validatorSetId,
      newValidatorSetId: valSet2.validatorSetId,
      lastFinalizedSeq_old: finalQC.commitSeq,
      lastFinalizedDigest_oldHex: finalQC.commitmentDigestHex,
      newGenesisSeq: 0n,
      transitionReason: 'ANNUAL_ROTATION',
      transitionTimestampUs: BigInt(Date.now()) * 1000n,
      oldEpochFinalQC: finalQC,
      customerAuthorization: {
        keyId: 'kms-root-01',
        customerPubkeyHex: customerPubkey.toString('hex'),
        signatureHex: '',
      },
    };
    const tcDig = computeEpochTransitionDigest(partialTC);
    const tcAuthPre = Buffer.concat([
      Buffer.from('WDB:CUST_EPOCH_AUTH:v1:', 'utf8'),
      tcDig,
      Buffer.from(valSet2.validatorSetId, 'utf8'),
    ]);
    const tcAuthDig = crypto.createHash('sha256').update(tcAuthPre).digest();
    partialTC.customerAuthorization.signatureHex = crypto.sign(null, tcAuthDig, customerKeypair.privateKey).toString('hex');
    const finalTcDig = computeEpochTransitionDigest(partialTC);

    const tc: CrossEpochTransitionCertificate = {
      ...partialTC,
      transitionCertificateDigestHex: finalTcDig.toString('hex'),
    };

    await journal.close();

    // 3. DESTROY THE CLOUD: All memory in v1Sm, gateway, coordinators, and frontier is wiped!
    // Retain only: journalPath on disk, qcs, tc, and valSet1/valSet2 registry.

    const disasterQueue = new DurableDisasterQueue(disasterQueuePath);
    const recoveryEngine = new TrustCloudRecoveryEngine(disasterQueue);

    const reloadedJournal = new DurableEvidenceJournal(journalPath);
    const valSets = new Map<number, ValidatorSetManager>([
      [1, valSet1],
      [2, valSet2],
    ]);

    // 4. Cold Recovery
    const recoveredState = await recoveryEngine.reconstructFromDurableHistory({
      bootstrapSnapshot: snapshot0,
      evidenceJournal: reloadedJournal,
      quorumCertificates: qcs,
      epochTransitionCertificates: [tc],
      validatorSetsByEpoch: valSets,
      customerPubkey,
    });

    expect(recoveredState.recoveredEpoch).toBe(2);
    expect(recoveredState.recoveredSequence).toBe(3n);
    expect(recoveredState.stateMerkleRootHex).toBe(preDestructionRootHex);
    expect(recoveredState.canFinalize).toBe(true);
    expect(recoveredState.activeDisastersCount).toBe(0);

    await reloadedJournal.close();
    await disasterQueue.close();
  });

  it('2. Disaster Invariant: Unverified recovery state cannot finalize new commitments', async () => {
    const disasterQueue = new DurableDisasterQueue(disasterQueuePath);
    // Artificially record an unresolved disaster
    disasterQueue.recordDisaster(DisasterType.D007_EQUIVOCATION_DETECTED, 'Unresolved equivocation proof pending review');

    const recoveryEngine = new TrustCloudRecoveryEngine(disasterQueue);
    const journal = new DurableEvidenceJournal(journalPath);

    const snapshot0: BootstrapSnapshot = {
      snapshotId: 'snap-0',
      snapshotLsn: '0/1000000',
      createdAtUs: 1723800000000000n,
      schemaEpoch: 1,
      tables: ['public.accounts'],
      rows: [],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    };

    const valSets = new Map<number, ValidatorSetManager>([[1, valSet1]]);

    const recovered = await recoveryEngine.reconstructFromDurableHistory({
      bootstrapSnapshot: snapshot0,
      evidenceJournal: journal,
      quorumCertificates: [],
      validatorSetsByEpoch: valSets,
      customerPubkey,
    });

    // Invariant: canFinalize must be FALSE while quarantined disasters exist
    expect(recovered.canFinalize).toBe(false);
    expect(recovered.activeDisastersCount).toBe(1);

    await journal.close();
    await disasterQueue.close();
  });
});
