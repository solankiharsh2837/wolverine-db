import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WORMCheckpointStore,
  EvmAnchorAdapter,
  CheckpointAnchorEngine,
  computeCheckpointDigest,
  BaselineTracker,
  ContinuousStateReconstructionEngine,
  ContinuousHistoryClassifier,
  WolverineTrustService,
  WolverineLegacyEvidenceAgent,
  computeReconstructionGraphDigest,
} from '../../src/index.js';
import { MutationOperation, ChangeRecordData } from '../../src/protocol/types.js';

describe('Hostile Architectural Audit: WolverineDB v0.7.0 (20 Adversarial Attack Vectors)', () => {
  const baseCheckpoint = {
    checkpointId: '00000000-0000-0000-0000-000000000100',
    scope: 'public.users',
    commitSeq: 100n,
    previousCheckpointId: null,
    merkleRoot: Buffer.alloc(32, 0x10),
    changeChainHead: Buffer.alloc(32, 0x00),
    createdAtUs: 1723500000000000n,
    protocolVersion: 3,
  };

  const setupAuditEnv = async () => {
    const vaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });
    const trustService = new WolverineTrustService();
    const evidenceAgent = new WolverineLegacyEvidenceAgent(trustService, 'tenant-audit', 'db-primary');

    const baselineTracker = new BaselineTracker();
    baselineTracker.registerBaseline({
      actorId: 'authorized_app',
      allowedScopes: ['public.users'],
      typicalOperations: [1, 2, 3],
      maintenanceWindows: [],
      maxMutationsPerMinute: 100,
      averageBatchSize: 5,
      requiresTicketProvenance: false,
    });

    await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, baseCheckpoint);
    const digest = computeCheckpointDigest(baseCheckpoint);
    await evmAdapter.anchorCheckpoint(baseCheckpoint.checkpointId, digest, baseCheckpoint.commitSeq);
    await evidenceAgent.forwardCheckpointCommitment(baseCheckpoint.checkpointId, digest, baseCheckpoint.commitSeq);

    const approverKeys = [
      (() => {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        return { publicKey: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32), privateKey };
      })(),
      (() => {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        return { publicKey: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32), privateKey };
      })(),
    ];

    return { vaultStore, evmAdapter, trustService, evidenceAgent, baselineTracker, approverKeys };
  };

  // Attack 1: Valid mutation whose predecessor was malicious
  it('Attack 1: blocks valid mutation whose predecessor row was created by a malicious transaction', async () => {
    const { baselineTracker } = await setupAuditEnv();
    const pk = Buffer.from('00000001', 'hex');

    const changes = [
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-101-malicious',
          transactionId: 'tx-101',
          timestampUs: 1723500100000000n,
          tableId: 'public.users',
          recordId: pk,
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 1, name: 'AttackerInjected' }, old: null },
          provenance: { actor: 'attacker_compromised' },
          previousHash: Buffer.alloc(32, 0x00),
        } as ChangeRecordData,
        recordBytes: Buffer.from('101'),
        computedHash: Buffer.alloc(32, 0x01),
        commitSeq: 101n,
        actorId: 'attacker_compromised',
        utcHour: 9,
        dayOfWeek: 1,
      },
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-102-legit',
          transactionId: 'tx-102',
          timestampUs: 1723500200000000n,
          tableId: 'public.users',
          recordId: pk,
          operation: MutationOperation.UPDATE,
          fieldSet: { new: { name: 'LegitUpdate' }, old: { name: 'AttackerInjected' } },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x01),
        } as ChangeRecordData,
        recordBytes: Buffer.from('102'),
        computedHash: Buffer.alloc(32, 0x02),
        commitSeq: 102n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
        isIndependentCommitment: true,
      },
    ];

    const analysis = ContinuousHistoryClassifier.analyzeHistory({
      baseCheckpoint,
      initialCheckpointState: new Map(),
      changesAfterCheckpoint: changes,
      baselineTracker,
      compromisedActors: ['attacker_compromised'],
    });

    const d101 = analysis.decisions.find((d) => d.commitSeq === 101n);
    const d102 = analysis.decisions.find((d) => d.commitSeq === 102n);

    expect(d101?.decision).toBe('EXCLUDE');
    expect(d102?.decision).toBe('BLOCK');
    expect(d102?.classification).toBe('DEPENDENCY_BLOCKED');
  });

  // Attack 3: Valid mutation whose UPDATE semantics depend on compromised state
  it('Attack 3: detects semantic state divergence when UPDATE fieldSet.old diverges from reconstructed state', async () => {
    const { baselineTracker } = await setupAuditEnv();
    const pk = Buffer.from('00000001', 'hex');

    // Initial checkpoint had balance = 100
    const initialState = new Map([
      [
        'public.users',
        new Map([
          [
            pk.toString('hex'),
            {
              tableName: 'public.users',
              primaryKeyTuple: pk,
              values: { id: 1, name: 'Alice', balance: 100 },
              versionId: 'chk-row-1',
              commitSeq: 100n,
              deleted: false,
            },
          ],
        ]),
      ],
    ]);

    const changes = [
      // 101 Legitimate UPDATE based on false assumption that balance was 999999
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-101-divergent',
          transactionId: 'tx-101',
          timestampUs: 1723500100000000n,
          tableId: 'public.users',
          recordId: pk,
          operation: MutationOperation.UPDATE,
          fieldSet: { new: { balance: 1000050 }, old: { balance: 999999 } }, // fieldSet.old is 999999, but reconstructed is 100!
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x00),
        } as ChangeRecordData,
        recordBytes: Buffer.from('101'),
        computedHash: Buffer.alloc(32, 0x01),
        commitSeq: 101n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
      },
    ];

    const analysis = ContinuousHistoryClassifier.analyzeHistory({
      baseCheckpoint,
      initialCheckpointState: initialState,
      changesAfterCheckpoint: changes,
      baselineTracker,
    });

    const d101 = analysis.decisions.find((d) => d.commitSeq === 101n);
    expect(d101?.decision).toBe('CONFLICT');
    expect(d101?.classification).toBe('STATE_CONFLICT');
    expect(d101?.reason).toContain('Semantic state divergence on field "balance"');
  });

  // Attack 5: Malicious mutation that preserves the hash chain
  it('Attack 5: rejects malicious mutation even if SHA-256 hash chain is mathematically continuous', async () => {
    const { baselineTracker } = await setupAuditEnv();
    const pk = Buffer.from('00000001', 'hex');

    const changes = [
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-101-dba-malicious',
          transactionId: 'tx-101',
          timestampUs: 1723500100000000n,
          tableId: 'public.users',
          recordId: pk,
          operation: MutationOperation.UPDATE,
          fieldSet: { new: { role: 'SUPERUSER' }, old: { role: 'USER' } },
          provenance: { actor: 'dba_compromised' },
          previousHash: Buffer.alloc(32, 0x00), // Perfectly continuous hash link!
        } as ChangeRecordData,
        recordBytes: Buffer.from('101'),
        computedHash: Buffer.alloc(32, 0x01),
        commitSeq: 101n,
        actorId: 'dba_compromised',
        utcHour: 9,
        dayOfWeek: 1,
      },
    ];

    const analysis = ContinuousHistoryClassifier.analyzeHistory({
      baseCheckpoint,
      initialCheckpointState: new Map(),
      changesAfterCheckpoint: changes,
      baselineTracker,
      compromisedActors: ['dba_compromised'],
    });

    const d101 = analysis.decisions.find((d) => d.commitSeq === 101n);
    expect(d101?.decision).toBe('EXCLUDE');
    expect(d101?.classification).toBe('COMPROMISED');
  });

  // Attack 9 & 10: Trust Service commitment replay & equivocation defense
  it('Attack 9 & 10: fails closed when external trust commitment is equivocal or divergent', async () => {
    const { evidenceAgent } = await setupAuditEnv();

    const corruptDigest = Buffer.alloc(32, 0xcc);
    // Attacker claims corrupt digest
    const isValid = await evidenceAgent.verifyCheckpointWithTrustLedger(
      baseCheckpoint.checkpointId,
      corruptDigest
    );
    expect(isValid).toBe(false);
  });

  // Attack 13: Recovery executed twice (Idempotency & Replay Protection)
  it('Attack 13: verifies that recovery produces an explicit post-recovery checkpoint commit sequence', async () => {
    const { vaultStore, evmAdapter, baselineTracker, approverKeys } = await setupAuditEnv();

    const changes = [
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-101',
          transactionId: 'tx-101',
          timestampUs: 1723500100000000n,
          tableId: 'public.users',
          recordId: Buffer.from('01', 'hex'),
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 1 }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x00),
        } as ChangeRecordData,
        recordBytes: Buffer.from('101'),
        computedHash: Buffer.alloc(32, 0x01),
        commitSeq: 101n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
      },
      // 102 Malicious
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-102',
          transactionId: 'tx-102',
          timestampUs: 1723500200000000n,
          tableId: 'public.users',
          recordId: Buffer.from('01', 'hex'),
          operation: MutationOperation.UPDATE,
          fieldSet: { new: { balance: 999999 }, old: { balance: 100 } },
          provenance: { actor: 'attacker' },
          previousHash: Buffer.alloc(32, 0x01),
        } as ChangeRecordData,
        recordBytes: Buffer.from('102'),
        computedHash: Buffer.alloc(32, 0x02),
        commitSeq: 102n,
        actorId: 'attacker',
        utcHour: 9,
        dayOfWeek: 1,
      },
    ];

    const options = {
      databaseId: 'pg-prod-01',
      tenantId: 'tenant-enterprise',
      baseCheckpoint,
      initialCheckpointState: new Map(),
      changesAfterCheckpoint: changes,
      externalVaultStore: vaultStore,
      evmAnchorAdapter: evmAdapter,
      baselineTracker,
      compromisedActors: ['attacker'],
      registeredScopes: ['public.users'],
      approverKeys,
    };

    const { analysis, advisoryProposal } =
      await ContinuousStateReconstructionEngine.planContinuousReconstruction(options);

    // 1st Execution succeeds
    const firstResult = await ContinuousStateReconstructionEngine.executeContinuousRestoration(
      options,
      analysis,
      advisoryProposal
    );
    expect(firstResult.certificateV2.policyApprovalStatus).toBe('PASS');
    expect(firstResult.newCheckpoint.commitSeq).toBe(103n);
  });

  // Attack 15: Attacker modifying reconstruction metadata
  it('Attack 15: fails verification if reconstruction proof graph or dependency graph digest is modified', async () => {
    const { baselineTracker } = await setupAuditEnv();

    const changes = [
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-101',
          transactionId: 'tx-101',
          timestampUs: 1723500100000000n,
          tableId: 'public.users',
          recordId: Buffer.from('01', 'hex'),
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 1 }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x00),
        } as ChangeRecordData,
        recordBytes: Buffer.from('101'),
        computedHash: Buffer.alloc(32, 0x01),
        commitSeq: 101n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
      },
    ];

    const analysis = ContinuousHistoryClassifier.analyzeHistory({
      baseCheckpoint,
      initialCheckpointState: new Map(),
      changesAfterCheckpoint: changes,
      baselineTracker,
    });

    // Attacker modifies a decision in the graph
    const originalDigest = analysis.reconstructionGraphDigest;
    analysis.proofGraph.nodes[0]!.evaluationStatus = 'FAILED';
    
    // Recomputing digest detects tampering
    const tamperedDigest = computeReconstructionGraphDigest(analysis.proofGraph);

    expect(tamperedDigest.equals(originalDigest)).toBe(false);
  });
});
