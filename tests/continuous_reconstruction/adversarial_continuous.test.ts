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
} from '../../src/index.js';
import { MutationOperation, ChangeRecordData } from '../../src/protocol/types.js';

describe('Adversarial Continuous Reconstruction Invariants (WDB-0070..0075)', () => {
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

  const setupEnv = async () => {
    const vaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });
    const baselineTracker = new BaselineTracker();
    baselineTracker.registerBaseline({
      actorId: 'authorized_app',
      allowedScopes: ['public.users'],
      typicalOperations: [1, 2],
      maintenanceWindows: [],
      maxMutationsPerMinute: 100,
      averageBatchSize: 5,
      requiresTicketProvenance: false,
    });

    await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, baseCheckpoint);
    const digest = computeCheckpointDigest(baseCheckpoint);
    await evmAdapter.anchorCheckpoint(baseCheckpoint.checkpointId, digest, baseCheckpoint.commitSeq);

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

    return { vaultStore, evmAdapter, baselineTracker, approverKeys };
  };

  it('case E & F: fractures contiguous frontier upon broken hash chain and excludes unanchored downstream changes', async () => {
    const { baselineTracker } = await setupEnv();

    const changes = [
      // 101 legitimate
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
      // 102 broken hash chain & unanchored
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-102',
          transactionId: 'tx-102',
          timestampUs: 1723500200000000n,
          tableId: 'public.users',
          recordId: Buffer.from('02', 'hex'),
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 2 }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0xee), // Broken!
        } as ChangeRecordData,
        recordBytes: Buffer.from('102'),
        computedHash: Buffer.alloc(32, 0x02),
        commitSeq: 102n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
        isIndependentCommitment: false,
      },
    ];

    const analysis = ContinuousHistoryClassifier.analyzeHistory({
      baseCheckpoint,
      initialCheckpointState: new Map(),
      changesAfterCheckpoint: changes,
      baselineTracker,
    });

    expect(analysis.contiguousVerifiedFrontierSeq).toBe(101n);
    const d102 = analysis.decisions.find((d) => d.commitSeq === 102n);
    expect(d102?.decision).toBe('EXCLUDE');
    expect(d102?.classification).toBe('MISSING');
  });

  it('case K: permanently excludes mutations signed by revoked keys', async () => {
    const { baselineTracker } = await setupEnv();

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
          provenance: { actor: 'revoked_key_actor' },
          previousHash: Buffer.alloc(32, 0x00),
        } as ChangeRecordData,
        recordBytes: Buffer.from('101'),
        computedHash: Buffer.alloc(32, 0x01),
        commitSeq: 101n,
        actorId: 'revoked_key_actor',
        utcHour: 9,
        dayOfWeek: 1,
      },
    ];

    const analysis = ContinuousHistoryClassifier.analyzeHistory({
      baseCheckpoint,
      initialCheckpointState: new Map(),
      changesAfterCheckpoint: changes,
      baselineTracker,
      revokedKeys: ['revoked_key_actor'],
    });

    const d101 = analysis.decisions.find((d) => d.commitSeq === 101n);
    expect(d101?.decision).toBe('EXCLUDE');
    expect(d101?.classification).toBe('REVOKED');
  });

  it('case M: verifies State Recovery Certificate V2 issued upon approved recovery execution', async () => {
    const { vaultStore, evmAdapter, baselineTracker, approverKeys } = await setupEnv();

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
          fieldSet: { new: { id: 1, name: 'Alice' }, old: null },
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

    const { certificateV2, terminalOutput } =
      await ContinuousStateReconstructionEngine.executeContinuousRestoration(
        options,
        analysis,
        advisoryProposal
      );

    expect(certificateV2.certificateVersion).toBe(2);
    expect(certificateV2.policyApprovalStatus).toBe('PASS');
    expect(certificateV2.cryptographicVerificationStatus).toBe('PASS');
    expect(certificateV2.preservedMutationIds).toEqual(['chg-101']);
    expect(certificateV2.excludedMutationIds).toEqual(['chg-102']);
    expect(terminalOutput).toContain('STATE RECOVERY CERTIFICATE (V2 EXTENDED)');
  });
});
